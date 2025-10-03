# 信息收集

## 路由信息
先看下路由信息（endpoints.py）有哪些路径可以走，以及权限设置，包括
- /local : 获取第一个flag，需要admin权限
- /admin：需要admin权限
- /chat.html: 用户权限可进入
- /index.html: 用户权限可以进
- /: 判断是否跳转到login.html
- /admin-login.html和login.html: 管理员页面有2fa多一个 twofa: twofa参数在请求token接口时
- /create_user.html：创建普通用户页面，不涉及权限，对接接口/user/create

## 接口信息
项目中关键的业务接口，不包含静态资源和状态检查接口，以及用于规范结构的函数
### auth
- /token：管理员和普通用户token发放jwt，jwt包含admin,username,role，函数包括：
    - authenticate_user：使用参数化sql请求函数验证用户登录信息,如果用户名是admin的登陆成功的jwt，会单独处理pyotp.HOTP，加双因素验证，普通用户不会，但是2fofa的计数器是固定值有种子就会爆破
    - create_access_token： token创建函数, 使用的jwt的secret被硬编码到setting.py里
## groups
- /group/create/：用户创建组，函数包括：
    - get_group_by_address：address参数用户可控，但是是参数化输入
    - create_group_controller：同上
    - await join_member_to_group: 同上
- /group/{group_id}/members：查看成员
    - group_membership_check ： group_id=group_id,db=db,user=current_user均参数化
    - group_members_by_id： 同上
- /group/join：用户加入组，管理员和普通用户都可以随意加入组
    - get_group_by_address：参数化请求
    - group_membership_check: 同上
    - join_member_to_group：同上
- /group/{group_id}/messages：查看群组消息
    - group_membership_check: 参数化请求
    - get_reads_messages: 同上
## message
- /message/{group_id}/first-unread-message: 读群组消息
    - group_membership_check: 参数化请求
    - get_first_unread_message_group: 同上
- /message/{message_id}：发消息，接口发现websocket作为群组消息广播，参数没有任何xss过滤
    - get_message_by_id：参数化请求
    - create_change_controller：把更新的消费传数据库里，只有参数化没有过滤
    - edit_message: 更新消息，消息泛型规定死了但是xss没有过滤
    - broadcast_changes：广播消息，同样没有xss过滤
        - send_change_to_user: 给在线用户发，没有过滤
## user
- /user/me：当前用户信息
    - get_current_user：通过jwt的username解密结果获取用户信息
        - decode_jwt：使用jwt解密
- /user/create：创建新用户，属性包括username，password，email，full_name
    - create_user_controller：参数化检查用户名是否已存在，加盐hash加密储存密码，不包含权限
- /user/groups：获取当前用户所属组
    - get_user_groups_by_id：从jwt里拉id再去拉所属组
- /api/attachments：从频道中获取attachments
    - download_attachments：从指定路径/home/student/chat_app/attachments/{channel}，但是channel用户可控制并且没有做过滤，禁止词汇["setting", "settings", "config"]，且过滤了txt文件结尾的输入
- /api/update-preferences：管理员权限才可以进入的接口，通过jwt的username是admin进行判断，不通过role
    - save_user_preferences_controller：序列化添加preference，参数包括：preferences，user_id
- /api/get-preferences: 同上是管理员入口
    - fetch_user_preferences：使用jsonpickle去反序列化处理用户的preference设置
## websocket
- /send-message: 用户token和group_id作为param放在websocket进行传输,检查身份和组员身份，通过直接组播，
- /get-unread-messages：把未读的消息发给用户，验证同上
# 情报分析和威胁建模
1. 不安全反序列化：管理员的/api/update-preference和/api/get-preferences
2. XSS：/message/{message_id}未做xss过滤
3. JWT secret 硬编码, 但是生产环境通过穿越看seed的值和debug环境不一样
4. 路径穿越：/api/attachments可以通过路径穿越，但是读取文件有限制
5. token通过get参数传输
6. cookie的httponly和secure都没有，但是samesite设置strict，cookie出不了域
7. 不安全的权限控制：管理员加入的组和普通用户加入组没有权限边界，任意用户可以加入管理员所属组，加入admin专属组Robert-23267会有管理员密码RainyPurpleDay8T2
8. 双因素认证绕过：双因素验证码为固定值，当前种子值计算为529175
9. 请求头和跨域没有限制
# 攻击链
创建任意用户 -> 加入admin组给管理员发xss -> 发送xss 获取管理员cookie -> 登录管理员获取第一个flag -> 反序列化反弹shell -> 获取proof.txt

