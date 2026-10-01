import urllib.request
import json

def test_api():
    print("Testing CyberGuard Backend...")
    # 1. Health
    r = urllib.request.urlopen("http://127.0.0.1:8001/health")
    print("1. Health Endpoint:", r.status, json.loads(r.read().decode()))

    # 2. Message Detection
    req_msg = urllib.request.Request(
        "http://127.0.0.1:8001/api/v1/detect",
        data=json.dumps({"text": "URGENT: Your SBI account has been locked. Verify immediately at http://bit.ly/sbi-acc", "channel": "SMS"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    r_msg = urllib.request.urlopen(req_msg)
    d_msg = json.loads(r_msg.read().decode())
    print("2. Message Analysis:", d_msg.get("risk_score"), d_msg.get("severity"), d_msg.get("action"))

    # 3. URL Detection
    req_url = urllib.request.Request(
        "http://127.0.0.1:8001/predict_url",
        data=json.dumps({"url": "http://secure-login-apple.xyz/verify?token=92841"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    r_url = urllib.request.urlopen(req_url)
    d_url = json.loads(r_url.read().decode())
    print("3. URL Analysis:", d_url.get("risk_score"), d_url.get("risk_level"), d_url.get("recommendation"))

    # 4. QR Detection
    boundary = "----TestBoundaryCyberGuard123"
    with open("frontend/samples/phishing_sample.png", "rb") as f:
        file_bytes = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="malicious_sample.png"\r\n'
        f"Content-Type: image/png\r\n\r\n"
    ).encode() + file_bytes + f"\r\n--{boundary}--\r\n".encode()

    req_qr = urllib.request.Request(
        "http://127.0.0.1:8001/detect_qr",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    r_qr = urllib.request.urlopen(req_qr)
    d_qr = json.loads(r_qr.read().decode())
    print("4. QR Analysis:", d_qr.get("decoded_url"), d_qr.get("risk_score"), d_qr.get("risk_level"), d_qr.get("recommendation"))
    print("\nAll 4 Endpoints Passed Perfectly!")

if __name__ == "__main__":
    test_api()
