# 信息收集
## 背景信息
- 项目代码类型：后端node.js，前端pug.js
- 部署工具: webpack
- 文件结构：
  - client-src:前端的静态文件和js文件，前端路由
  - server-src:后端api
  - app.js: 程序入口
## 配置信息
- webpack.config.js：client-src前端入口打包配置，没有发现，开启了disk
- application_setting.json: 开启websocket
- app.js: 中间件路由，所有请求要走的中间件包括customAuthMiddleware，customDocMiddleware，customPluginMiddleware
- server-src/settings.js: 后端配置，debug的mysql账号是root，密码71bfaf52714a338c3bc34add6d1d12716bed0f1d76cb2602d119aa425307feb8，数据库为docedit。连接命令mysql -h 127.0.0.1 -u root
## 前端路由信息
先看下路由信息有哪些路径可以走，以及权限设置，包括：
- 无需授权：
  - /home: 主页
  - /login：登录
  - /register: 注册
- 需要授权
  - /logout：登出
  - /d/delete/:id和/document/delete/:id：文件删除
  - /d/:id和/document/:id'：指定文件
  - /d和/document：新文件
  - /profile：用户个人信息编辑
  - /server：管理员用户查看server配置

## 接口信息
项目中关键的业务接口，不包含静态资源和状态检查接口，以及用于规范结构的函数
- 前置路由
  - custom-auth-middleware-ws：websocket验证token通过findone方法，虽然没有过滤但是使用Sequelize，会将方法参数化
  - custom-auth-middleware.js：同上，但是'/','/login','/register','logout'不用授权，x-local-storage-token的请求头存在会用这个请求头进行身份验证，或者cookie或者authorization请求头
  - custom-doc-middleware-ws.js：Sequelize列出当前用户的所有doc
  - custom-doc-middleware.js：同上
  - custom-plugin_loaded-middleware-ws.js：如果pluginController.enabledPlugins()了，就获取ws的插件
  - custom-plugin_loaded-middleware.js：如果pluginController.enabledPlugins()了，就获取traditional的插件
- 普通用户
  - /flag：读第一个旗子，不用授权就可以，前端校验
  - /login：需要email和password两个参数，cookie设置了httponly，登录成功使用User的authorize原型，使用math.random创建token
    - AuthToken：generate属性，创建token使用Math.random() 
  - /register：firstName，lastName，email，password1，password2，注册需要的参数，email作为用户是否存在的判断,参数化了
  - /profile/update：跟注册一样，更新账号密码，用的userController
    - searchByEmail: 存在sql拼接而不是参数化输入
  - /document或者/d： 创建doc，参数化创建，但是title和content后端没有xss校验
  - /document/:docid或者/d/:docid：查看指定doc渲染到pug模板中，走的doc的controller，local校验用户身份
  - /document/tag/:docid：修改tag
- Websocket路由
  - updateProfile：更新用户信息，使用usercontroller，输入没有过滤，参数有data.firstName, data.lastName, data.email,data.password1,data.password2
- 管理员用户
  - /server：走的plugin controller
    - pluginController.js: 使用了eval函数执行location变量，且该变量用户可控制，虽然设置了黑名单blacklist = ["require", "child_process"]但是可以被绕过
  - /plugin/:name/:enable：控制是否开启plugin
# 情报分析和威胁建模
1. 权限管理不当：flag只要注册用户就能读到
2. token使用伪随机Random：使用了伪随机，可以直接爆破出来
3. cookie：虽然有js的控制，但是没有失效时间控制
4. 储存型XSS： doc可以写入js代码，toggle会弹xss
5. 模板注入：server接口的plugin，用户可控制的location参数执行代码
6. SQL注入：更新email的profil时，使用字符串拼接，可能导致sql注入
# 攻击链
注册用户 -> 进入用户获取第一个flag -> 更新profile的email使用盲注获取管理员token -> 进入管理员用户 -> 通过/server进行模板注入执行命令