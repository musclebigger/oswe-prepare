# 信息收集
## 背景信息
- 项目代码类型：php
- 部署工具: apache2
## 配置信息
- 数据库：mysql，表OffsecGallery，登录命令```mysql -h 127.0.0.1 -u root -pDebugOffsecGallery888```，admin账号密码：admin@offsec.com：DebugAdminPassword000, 存在tbl_user表
- .htaccess: 禁止上传的文件php|php1|php2|php3|php4|php5|php6|php7|php8|php9|php10|php11|php12|phtml|pht|phar|phps
- uploads：存在可读的文件上传路径/assets/uploads
## 路由信息
路径有点多，先看下关键路由信息有哪些以及权限设置，包括：
1.普通用户customer：
- verify.php: 身份验证路由，但是发现如果没有token或者email，可以更新任意用户的cust_token和cust_status在tbl_customer表
- registration.php: cust_email参数在注册时可以枚举，validation_code参数可以爆破的rand函数0-999，使用md5编码token取的是time()，并且没有对参数过滤
- forget-password.php: cust_email也是存在枚举，md5的随机数rand()的token，message参数中的reset-password.php?email=*&token=*可以发包含xss的邮件信息。但是数据库表是tbl_customer，而且email必须存在，token用的md5和rand()生成
- reset-password.php:没有email或者没有token才都会直接跳到login，token必须在数据库里有，但是token的验证仅在进入重置密码的表单，但是表单的发送只验证email，不会验证用户的身份token就直接更新，用的表在tbl_customer，但是在此之前数据库取数时token和email要对应上
- export-orders.php: 禁止导出包含'local.txt', 'proof.txt'的文件，exports路径被写死了，但是文件名过滤存在问题，拼接了fullname能读除了禁止的其他文件
- customer-password-update.php:跟reset不同，是通过session中的用户id判断的，有权限限制
- customer-profile-update.php: 不存在文件上传路径，仅能修改信息，sql都参数化的
- search-result.php: 怀疑search_text的搜索参数，存在反射xss，没有任何过滤。但是实际特殊符号被删除掉了
2.管理员admin:
- login.php：账号密码登录，返回的md5进行匹配密码
- monitor.php: 命令执行，但是使用了trim而且限制了开头必须是'ls', 'whoami', 'id', 'mysql', 'cat'以及这些符号'&', '#', ';', '`', '|', '*', '?', '~', '<', '>', '^', '(', ')', '[', ']', '{', '}', '$', ',', '\x0A', '\xFF'
- photo-add.php和product-add.php和profile-edit.php和service-add.php和settings.php: 仅检查文件后缀使用pathinfo，但是会改名字在move_uploaded_file之前
- inc/config.php: 硬编码管理员账号admin@offsec.com密码DebugAdminPassword000
# 情报分析和威胁建模
- 用户信息枚举：registration可以邮箱进行枚举用户的email
- 命令执行：存在直接操控命令函数
- 使用弱加密：使用md5，在注册时的token，就是创建时间的md5
- 硬编码： 管理员账号密码被配置到config.php中
- 验证码爆破：由于仅在0-999范围内，没有限制爆破出唯一值
- 文件包含：export-orders.php没有对filename进行过滤处理，导致可以读取任意文件，如果用户名cust_name为恶意的对导致文件读取
# 攻击链
get注册拿到csrftoken(测试发现csrf token不生效) -> 注册一个可以文件包含的用户名字（这里需要相对路径../admin/inc/config.php） -> md5爆破出validation_token作为登录的validation_code登录账户（需要先get login取csrftoken才行，找到302就是成功） -> LFI文件包含读取inc的管理员密码 -> 管理员入口登录 -> 命令执行command=cat+..%2Fproof.txt