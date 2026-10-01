import os
import sys
import cv2
import json
import numpy as np
import qrcode

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from url_intelligence.qr.decoder import QRDecoder

# Path configurations
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
QR_SAMPLES_DIR = os.path.join(TEST_DIR, 'qr_samples')
os.makedirs(QR_SAMPLES_DIR, exist_ok=True)

test_cases = [
    # Benign
    {"name": "benign_1.png", "url": "https://wikipedia.org", "type": "normal"},
    {"name": "benign_2.png", "url": "https://google.com/search?q=cybersecurity", "type": "small"},
    {"name": "benign_3.png", "url": "http://example.com/about", "type": "rotated_90"},
    {"name": "benign_4.png", "url": "https://github.com", "type": "low_contrast"},
    {"name": "benign_5.png", "url": "https://ubuntu.com/download", "type": "inverted"},
    
    # Malicious
    {"name": "malicious_1.png", "url": "http://secure-login-apple.xyz", "type": "normal"},
    {"name": "malicious_2.png", "url": "https://update-paypal-notice.com/verify", "type": "noisy"},
    {"name": "malicious_3.png", "url": "http://bit.ly/malicious-link", "type": "rotated_180"},
    {"name": "malicious_4.png", "url": "https://free-netflix-subscription.tk", "type": "small"},
    {"name": "malicious_5.png", "url": "http://verify-bank-details.com/login.php", "type": "low_contrast"}
]

def generate_samples():
    print("Generating diverse QR test samples...")
    for case in test_cases:
        filepath = os.path.join(QR_SAMPLES_DIR, case['name'])
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(case['url'])
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
        cv_img = np.array(img)
        cv_img = cv_img[:, :, ::-1].copy() # RGB to BGR
        
        # Apply augmentations based on type
        if case['type'] == 'small':
            cv_img = cv2.resize(cv_img, (50, 50), interpolation=cv2.INTER_AREA)
        elif case['type'] == 'rotated_90':
            cv_img = cv2.rotate(cv_img, cv2.ROTATE_90_CLOCKWISE)
        elif case['type'] == 'rotated_180':
            cv_img = cv2.rotate(cv_img, cv2.ROTATE_180)
        elif case['type'] == 'low_contrast':
            cv_img = cv2.convertScaleAbs(cv_img, alpha=0.3, beta=100) # reduce contrast
        elif case['type'] == 'inverted':
            cv_img = cv2.bitwise_not(cv_img)
        elif case['type'] == 'noisy':
            noise = np.random.randint(0, 50, cv_img.shape, dtype='uint8')
            cv_img = cv2.add(cv_img, noise)
            
        cv2.imwrite(filepath, cv_img)

def run_evaluation():
    decoder = QRDecoder()
    total = 0
    successful = 0
    failed = 0
    
    print("\n" + "="*40)
    print("QR DECODER TEST RUN")
    print("="*40)
    
    for filename in os.listdir(QR_SAMPLES_DIR):
        if not filename.endswith(('.png', '.jpg', '.jpeg', '.webp')):
            continue
            
        total += 1
        filepath = os.path.join(QR_SAMPLES_DIR, filename)
        
        # We need size and details for the log
        img = cv2.imread(filepath)
        h, w, c = img.shape
        size_kb = os.path.getsize(filepath) / 1024
        
        res = decoder.decode_image(filepath)
        
        print("\nQR DEBUG")
        print("--------")
        print(f"Filename: {filename}")
        print(f"File size: {size_kb:.2f} KB")
        print(f"Image dimensions: {w}x{h}")
        print("Decoder used: OpenCV QRCodeDetector (with Preprocessing Pipeline)")
        
        if res['success']:
            successful += 1
            print(f"Detection result: SUCCESS")
            print(f"Decoded payload: {res['raw_content']}")
        else:
            failed += 1
            print(f"Detection result: FAILED")
            print(f"Reason: {res['error']}")
            
    print("\n" + "="*40)
    print("QR DECODER TEST SUMMARY")
    print("="*40)
    print(f"Total: {total}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    rate = (successful / total) * 100 if total > 0 else 0
    print(f"Decode Rate: {rate:.1f}%")

if __name__ == "__main__":
    generate_samples()
    run_evaluation()
