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
- server-src/settings.js: 后端配置，debug的mysql账号是docedit，密码80c2680bb8b8113d57147c25bd371f2b7cffcfa22a9456d444f97ad6f92b70ce，数据库为docedit。连接命令mysql -h 127.0.0.1 -u docedit -p 80c2680bb8b8113d57147c25bd371f2b7cffcfa22a9456d444f97ad6f92b70ce
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

- 普通用户

- 管理员用户

# 情报分析和威胁建模

# 攻击链