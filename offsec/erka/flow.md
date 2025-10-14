# 信息收集
## 背景信息
- 项目代码类型：php
- 部署工具: apache2
## 配置信息
数据库：使用MySQL数据库，表名website，为连接方法 ```mysql -h 127.0.0.1 -u root -prootpassword888!```，包含用户的表users。表重管理员角色信息：username:admin,first_name:Eric,last_name:Wek,email:eric.wek@erka.com，roleid：1, backup_password:Ui3LcAnEyvH2 。默认普通用户Ali,Jane,Andrea,Vlads，roleid为1。Alex为moderator角色roleid为2。查看mysql.func没有内置UDF。
## 路由信息
先看下路由信息有哪些路径可以走，以及权限设置，包括：
- pages
    - index.php：主页
    - sign-up.php: 注册页面，参数化sql并且输入过滤，并且会防用户名重复
    - sign-in.php: 用户登录页面，同上
    - profile.php: 检查session中的login，查看用户的profile，sql都参数化了，但是查询用户的id没有对用户去权限限制
    - profile-edit.php: 可以上传文件，设置了文件名白名单,但仅对扩展名进行了处理，未验证文件类型，修改的sql都参数化
    - profile-card.php: 当userid为异常值时，receiver_id作为参数传参是用来sql拼接，导致sql注入
    - post.php: header的信息
- components/header.php：检查session中是否isadmin和loggedin，如果都符合，返回第一个flag
- components/admin
    - admin/file_storage.php:管理员权限，上传文件依旧是白名单控制，存在权限检查，但是move_uploaded_file在检查扩展名前就传上去了
    - admin/user_management.php: 管理员权限，用于用户管理，增删改查，均参数化。存在权限检查
- components/content
    - category-list.php: 从数据库拉category数据，参数化请求，不存在用户控制输入
    - share-post.php: 分享，分享内容没有xss过滤

# 情报分析和威胁建模
- cookie固定和：登录前登录后cookie一致，没有secure但是又httponly
- 储存型xss： share-post.php没有对上传内容过滤导致界面弹窗
- 用户名枚举: 通过/pages/profile.php可以枚举用户profile信息
- sql注入: profile-card.php传入userid为异常值被关注者未做过输入过滤，携带session发送请求，导致sql注入,payload为```/pages/profile.php?user_id=14&receiver_id=1/**/UNION/**/SELECT/**/NULL,NULL,NULL,NULL```,这里建议bool盲注，根据回复的报文Follow和Followed的差异，比时间盲注稳定```/pages/profile.php?user_id=14&&receiver_id=2/**/AND/**/(SELECT/**/SUBSTRING(backup_password,1,1)/**/FROM/**/users/**/WHERE/**/username='admin')='U'```。尝试了多条件查询```1";UPDATE/**/users/**/SET/**/role_id=1/**/WHERE/**/username="frank"```注入发现不支持没反应，只支持单条件查询
- 任意文件上传：尽管报错，但是由于move_uploaded_file在检查扩展名前就传上去，只要能猜到文件名，就能读取上传恶意文件
# 攻击链
注册用户 -> 登录用户 -> 在profile页面发送关注请求/pages/index.php确认发送的receiver_id为正确值 -> /pages/profile.php触发sql使用从users库的admin的backup_password,利用receiver_id的正确和错误id回显不止 -> 获取flag -> 进入管理员账户 -> 上传恶意文件后门<?php readfile('/proof.txt');?> -> rand的数字爆破50个数后进入后门
