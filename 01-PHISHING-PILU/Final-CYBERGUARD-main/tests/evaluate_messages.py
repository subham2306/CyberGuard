import os
import sys
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from cyberguard.api import get_hub

def evaluate_messages():
    hub = get_hub()

    benign_messages = [
        "Hey bro, are you coming to college tomorrow?",
        "Can you send me the notes?",
        "Happy birthday! Have a great day.",
        "Let's meet at 6 PM.",
        "Your assignment looks good.",
        "Please verify the assignment details.",
        "Send me the account number for the college project.",
        "Check out this article: https://en.wikipedia.org/wiki/Computer_security",
        "Can we reschedule our meeting to 3 PM?",
        "I'll call you back in 10 minutes."
    ]

    phishing_messages = [
        "Your account will be suspended today. Verify your account immediately at http://bit.ly/update-now",
        "Congratulations! You won Rs 50,000. Click the link to claim your prize.",
        "Your bank account has been blocked. Login immediately to verify.",
        "Your KYC has expired. Send your OTP to reactivate your account.",
        "URGENT: Unauthorized login attempt detected. Secure your account now.",
        "Dear customer, your debit card is blocked. Call 1800-XXX-XXXX immediately.",
        "Payment of $500 received. If you did not authorize this, click here to cancel.",
        "Please review the attached invoice for your recent purchase.",
        "You have a pending package delivery. Pay the $2 shipping fee here.",
        "Action Required: Update your Apple ID billing information."
    ]

    print("=== BENIGN MESSAGES ===")
    for msg in benign_messages:
        res = hub.predict_message(msg)
        print(f"Text: {msg}")
        print(f"Prob: {res['raw_probability']} -> Calibrated: {res['calibrated_probability']} -> Score: {res['risk_score']} ({res['severity']})")
        print(f"Explanation: {res['explanation']}")
        print("-")

    print("=== PHISHING MESSAGES ===")
    for msg in phishing_messages:
        res = hub.predict_message(msg)
        print(f"Text: {msg}")
        print(f"Prob: {res['raw_probability']} -> Calibrated: {res['calibrated_probability']} -> Score: {res['risk_score']} ({res['severity']})")
        print(f"Explanation: {res['explanation']}")
        print("-")

if __name__ == "__main__":
    evaluate_messages()
