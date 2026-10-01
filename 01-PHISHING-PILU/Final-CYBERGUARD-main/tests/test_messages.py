"""
CyberGuard Message Phishing Test Suite
Tests benign messages, financial alerts, account threats, and credential harvesting patterns.
"""
import os
import sys

# Ensure project root is in sys.path for direct execution
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from cyberguard.api import get_hub

def run_message_tests():
    hub = get_hub()
    test_cases = [
        # Benign conversational samples
        ("Hey, are you coming to college tomorrow?", "SMS", "LOW"),
        ("Can you send me the assignment notes when you're free?", "SMS", "LOW"),
        ("Happy birthday! Have a wonderful day.", "SMS", "LOW"),
        ("Let's meet at 6 PM in the lab.", "SMS", "LOW"),
        ("Check out this article: https://en.wikipedia.org/wiki/Computer_security", "SMS", "LOW"),
        # Suspicious / Phishing samples
        ("URGENT: Your SBI bank account has been suspended. Verify immediately at http://bit.ly/sbi-acc", "SMS", "CRITICAL"),
        ("Action Required: Update your Apple ID billing information immediately.", "EMAIL", "HIGH"),
        ("Congratulations! You won Rs 50,000 cash prize. Click the link to claim now.", "SOCIAL", "HIGH"),
        ("Your KYC has expired. Send your OTP immediately to reactivate your banking services.", "SMS", "CRITICAL")
    ]

    print("=" * 70)
    print("           CYBERGUARD MESSAGE INFERENCE TEST SUITE")
    print("=" * 70)

    passed = 0
    for text, channel, expected_sev in test_cases:
        res = hub.predict_message(text, channel)
        score = res['risk_score']
        sev = res['severity']
        action = res['action']
        status = "PASS" if (expected_sev == "LOW" and score < 50) or (expected_sev in ("HIGH", "CRITICAL") and score >= 50) else "WARN"
        if status == "PASS":
            passed += 1
        print(f"[{status}] Score: {score:3d} | Severity: {sev:8s} | Action: {action:15s} | Channel: {channel:5s}")
        print(f"       Text: \"{text[:65]}...\"")

    print("=" * 70)
    print(f"Summary: {passed}/{len(test_cases)} tests aligned with expected security threshold.")
    print("=" * 70)

if __name__ == "__main__":
    run_message_tests()
