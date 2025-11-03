# 信息收集
## 背景信息
- 项目代码类型：python
- 部署工具: 黑盒测试，提供了攻击链
- 路径扫描：gobuster dir -url http://192.168.209.248 -w /usr/share/dirb/wordlists/common.txt --proxy http://127.0.0.1:8080 -f --exclude-length 961，必须设置长度判断要不然全是200，而且要加-f要不然全是301
# 情报分析和威胁建模
文件信息：路径/home/student/sqeakr/sqeakr/
- wsgi.py
- custom.py
- urls.py
- .env
- settings.py

威胁已经写在了背景介绍里，包括：
1. 路径穿越获取敏感信息
2. 操纵token进行越权
3. pickle反序列化
4. 任意文件上传
5. 敏感信息泄露：/robots.txt里泄露了路径包括：
```
User-agent: *
Disallow: /api/login
Disallow: /api/register/
Disallow: /api/compose
Disallow: /api/draft
Disallow: /api/profile/update
Disallow: /api/profile/upload
Disallow: /api/profile/preview/*
Disallow: /api/profile/approve/*
Disallow: /api/profile/password
Disallow: /api/avatars/*
Allow: /api/sqeaks
Allow: /feed
```
/api/sqeaks泄露了一些用户信息
# 攻击链
首先在robots.txt里找到/api/profile/preview/*和/api/avatars/*，这两个路径/api/avatars/可以路径穿越，但是要求是穿越需要/....//..../进行绕过至少四层，/api/profile/preview/去读，需要base64编码,而且穿越路径至少四层 -> 拿到默认验证码 -> /api/flag创建成功就是第一个flag（其实穿越到/home/student/sqeakr就能看到proof.txt)了
