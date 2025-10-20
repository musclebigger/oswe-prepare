# 信息收集
## 背景信息
- 项目代码类型：php
- 部署工具: apache2
## 配置信息
- 数据库：mysql，表OffsecGallery，登录命令```mysql -h 127.0.0.1 -u root -pDebugOffsecGallery888```，admin账号密码：admin@offsec.com：DebugAdminPassword000
- .htaccess: 禁止上传的文件php|php1|php2|php3|php4|php5|php6|php7|php8|php9|php10|php11|php12|phtml|pht|phar|phps
- uploads：存在可读的文件上传路径/assets/uploads
## 路由信息
路径有点多，先看下关键路由信息有哪些以及权限设置，包括：
1.普通用户customer：
- verify.php: 身份验证路由，但是发现如果没有token或者email，可以更新任意用户的cust_token和cust_status在tbl_customer表
- registration.php: cust_email参数在注册时可以枚举，validation_code参数可以爆破0-999
- forget-password.php: cust_email也是存在枚举，md5的随机数rand()的token，message参数中的reset-password.php?email=*&token=*可以发包含xss的邮件信息
- reset-password.php:没有email或者没有token才会直接跳到login，token必须在数据库里有，但是token的验证仅在进入重置密码的表单，但是表单的发送只验证email，不会验证用户的身份token就直接更新
- export-orders.php: 禁止导出包含'local.txt', 'proof.txt'的文件，exports路径被写死了
- customer-password-update.php:跟reset不同，是通过session中的用户id判断的，有权限限制
- customer-profile-update.php: 不存在文件上传路径，仅能修改信息，sql都参数化的
- search-result.php: search_text的搜索参数，存在反射xss，没有任何过滤
2.管理员admin:
- login.php：账号密码登录，返回的md5进行匹配密码
- monitor.php: 命令执行，但是使用了trim而且限制了开头必须是'ls', 'whoami', 'id', 'mysql', 'cat'以及这些符号'&', '#', ';', '`', '|', '*', '?', '~', '<', '>', '^', '(', ')', '[', ']', '{', '}', '$', ',', '\x0A', '\xFF'
- photo-add.php和product-add.php和profile-edit.php和service-add.php和settings.php: 仅检查文件后缀使用pathinfo，但是会改名字在move_uploaded_file之前
# 情报分析和威胁建模
用户信息枚举：registration可以邮箱进行枚举用户的email
未授权密码重置：仅通过email进行判断重置密码的用户信息，导致普通用户可修改任意用户密码
命令执行：存在直接操控命令函数
验证码爆破：注册3位验证码，可以爆破任意未注册用户验证码
xss反射：搜索和发邮件都未对javascrip的代码进行过滤

# 攻击链