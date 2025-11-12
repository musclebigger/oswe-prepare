import requests

# Get a session
session = requests.Session()
r = session.get('http://localhost:1337/list')
print(f"Status: {r.status_code}")
print(f"\nHeaders:")
for header, value in r.headers.items():
    print(f"  {header}: {value}")

print(f"\nCSP Header: {r.headers.get('Content-Security-Policy', 'Not found')}")
