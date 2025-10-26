# 信息收集
## 背景信息
- 项目代码类型：node.js
- 部署工具: npm
## 配置信息
- 数据库：库notebook，数据库连接```mysql -h 127.0.0.1 -u root -pGreenBook99```
- 前/后端.env:JWT_SECRET=57157123561238957120375210893529572571290571271025720375825

## 路由信息
先看下路由信息有哪些路径可以走，以及权限设置，包括:
- 前端：addnote, editnote, filestorage, register, login, profile, viewnote, listusers,flag在home里，如果localStorage的token对了才能拿到第一个flag
  - login：后端返回token就回到/的dashboard
  - home: localstorage有token的参数就可以进，但是请求需要token验证
  admin权限：
  - listuser： 后端token验证
  - filestorage: admin权限上传文件
## 接口信息
项目中关键的业务接口，不包含静态资源和状态检查接口，以及用于规范结构的函数
- 中间件：环境变量里取jwt code，token是jwt，用的jsonwebtoken库
普通用户usercontroller
- /register：使用，express-validator库验证请求最新版本，email会验证导致用户枚举
- /login: 不存在枚举，jwt token
- /profile：get方法的req.user.id来自于jwt解码后的userid，更新用户名或者邮件会刷新jwt，但是更新用户使用了一个merge函数进行了完全递归的拷贝导致原型链污染__proto__:{isAdmin:"true"}导致分发admin JWT, 也没有邮箱校验
- /note：参数化操控数据库
管理员用户adminController
- /plugin: 三个plugin，输入通过/admin/plugin?plugin=sysinfo方式call组件，路径在请求时被指定了，文件名也写死了
- /storage：直接把名字全随机化了，但是会执行解压任意文件，随机化使用弱随机Math.random()但是0到1间任意浮点数
# 情报分析和威胁建模
- 用户枚举：注册可以枚举用户名
- 原型链污染：profile修改时，使用{"__proto__": {"isAdmin": "true"}, "email": "admin1@offsec.com", "username": "admin1"}，将当前token用户权限修改
- 任意文件上传： storage上传的文件会解压任意文件，并存到uploads中，并且没有对文件名做过滤，导致解压到指定目录, 但是注意坑点怎么去创建带路径的文件名，linux会创建不了，用zipfile压缩时的重命名才行
# 攻击链
注册用户 -> 登录用户 -> 修改用户profile，原型链污染成admin（注意要发两次可能异步的bug导致）-> 切换jwt，文件上传恶意文件 -> 读取插件js，执行任意文件读取(注意异步的问题，魔改的源码中的读flag)