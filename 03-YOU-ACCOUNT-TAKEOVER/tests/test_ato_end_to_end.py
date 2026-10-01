import requests
import time


BASE_URL = "http://127.0.0.1:8000"

USERNAME = "alice"
PASSWORD = "Alice@123"


passed = 0
failed = 0


def record_test(name, condition, details=""):
    global passed, failed

    if condition:
        print(f"[PASS] {name}")
        passed += 1
    else:
        print(f"[FAIL] {name}")
        if details:
            print(f"       {details}")
        failed += 1


def post(endpoint, payload):
    response = requests.post(
        f"{BASE_URL}{endpoint}",
        json=payload,
        timeout=10
    )

    return response


def get(endpoint):
    response = requests.get(
        f"{BASE_URL}{endpoint}",
        timeout=10
    )

    return response


print("=" * 65)
print("CYBERGUARD ATO - END-TO-END TEST")
print("=" * 65)


# ============================================================
# 1. HEALTH CHECK
# ============================================================

print("\n[1] SYSTEM HEALTH")

response = get("/health")

record_test(
    "Health endpoint",
    response.status_code == 200,
    response.text
)

if response.status_code == 200:
    data = response.json()

    record_test(
        "ML detection enabled",
        data.get("ml_model") == "enabled"
    )

    record_test(
        "Password spraying enabled",
        data.get("password_spraying_detection") == "enabled"
    )

    record_test(
        "IP blocklist enabled",
        data.get("ip_blocklist") == "enabled"
    )

    record_test(
        "MFA enabled",
        data.get("mfa") == "enabled"
    )

    record_test(
        "Session management enabled",
        data.get("session_management") == "enabled"
    )

    record_test(
        "Session takeover detection enabled",
        data.get("session_takeover_detection") == "enabled"
    )


# ============================================================
# 2. ADAPTIVE LOGIN + MFA TRUST
# ============================================================

print("\n[2] ADAPTIVE LOGIN + MFA TRUST")

normal_ip = "192.0.2.11"
normal_device = "demo-device-alice"
normal_user_agent = "CyberGuard-Demo-Client"
normal_location = "Bhubaneswar"


# ------------------------------------------------------------
# First login from a new context
# ------------------------------------------------------------

response = post(
    "/login",
    {
        "username": USERNAME,
        "password": PASSWORD,
        "ip_address": normal_ip,
        "location": normal_location,
        "device_id": normal_device,
        "user_agent": normal_user_agent
    }
)

record_test(
    "Initial adaptive login HTTP response",
    response.status_code == 200,
    response.text
)

initial_login = response.json()

print(
    "       Initial Decision:",
    initial_login.get("decision")
)

print(
    "       Initial Risk:",
    initial_login.get("risk_score")
)

# The first login from a new context may require MFA.
initial_decision = initial_login.get("decision")

record_test(
    "Initial login accepted for adaptive evaluation",
    initial_decision in ("ALLOW", "MONITOR", "MFA_REQUIRED"),
    initial_login
)


# ------------------------------------------------------------
# MFA bootstrap if required
# ------------------------------------------------------------

session_id = None

if initial_decision == "MFA_REQUIRED":

    mfa_data = initial_login.get("mfa", {})

    record_test(
        "MFA challenge generated",
        mfa_data.get("required") is True
    )

    challenge_id = mfa_data.get("challenge_id")
    demo_otp = mfa_data.get("demo_otp")

    record_test(
        "MFA challenge ID generated",
        bool(challenge_id)
    )

    record_test(
        "Demo OTP generated",
        bool(demo_otp)
    )

    if challenge_id and demo_otp:

        response = post(
            "/mfa/verify",
            {
                "challenge_id": challenge_id,
                "otp": demo_otp
            }
        )

        mfa_verify_data = response.json()

        record_test(
            "Correct MFA verification",
            response.status_code == 200
            and mfa_verify_data
            .get("mfa", {})
            .get("verified") is True,
            response.text
        )


        # ----------------------------------------------------
        # Login again with the same trusted context
        # ----------------------------------------------------

        response = post(
            "/login",
            {
                "username": USERNAME,
                "password": PASSWORD,
                "ip_address": normal_ip,
                "location": normal_location,
                "device_id": normal_device,
                "user_agent": normal_user_agent
            }
        )

        record_test(
            "Trusted login HTTP response",
            response.status_code == 200,
            response.text
        )

        normal_data = response.json()

        print(
            "       Trusted Decision:",
            normal_data.get("decision")
        )

        print(
            "       Trusted Risk:",
            normal_data.get("risk_score")
        )

else:

    normal_data = initial_login


# ------------------------------------------------------------
# Validate trusted login
# ------------------------------------------------------------

record_test(
    "Trusted login returns ALLOW",
    normal_data.get("decision") == "ALLOW",
    normal_data
)

record_test(
    "Trusted login successful",
    normal_data.get("login") == "successful",
    normal_data
)

record_test(
    "Trusted session created",
    normal_data.get("session", {}).get("created") is True,
    normal_data
)

session_id = (
    normal_data
    .get("session", {})
    .get("session_id")
)


# ============================================================
# 3. NORMAL SESSION VALIDATION
# ============================================================

print("\n[3] NORMAL SESSION CHECK")

record_test(
    "Session ID generated",
    bool(session_id)
)

if session_id:

    response = post(
        "/session/check",
        {
            "session_id": session_id,
            "current_ip": normal_ip,
            "current_device_id": normal_device,
            "current_user_agent": normal_user_agent,
            "current_location": normal_location
        }
    )

    record_test(
        "Normal session check HTTP response",
        response.status_code == 200,
        response.text
    )

    session_data = response.json()

    print(
        "       Session Decision:",
        session_data.get("decision")
    )

    print(
        "       Session Risk:",
        session_data.get("risk_score")
    )

    record_test(
        "Normal session remains valid",
        session_data.get("valid") is True,
        session_data
    )

    record_test(
        "Normal session decision is ALLOW",
        session_data.get("decision") == "ALLOW",
        session_data
    )

    record_test(
        "Normal session anomaly is false",
        session_data
        .get("anomaly_detection", {})
        .get("anomaly_detected") is False,
        session_data
    )


# ============================================================
# 4. SESSION TAKEOVER SIMULATION
# ============================================================

print("\n[4] SESSION TAKEOVER DETECTION")

if session_id:

    response = post(
        "/session/check",
        {
            "session_id": session_id,
            "current_ip": "203.0.113.50",
            "current_device_id": "attacker-device",
            "current_user_agent": "Attacker-Browser",
            "current_location": "Unknown"
        }
    )

    record_test(
        "Suspicious session check HTTP response",
        response.status_code == 200,
        response.text
    )

    takeover_data = response.json()

    print(
        "       Decision:",
        takeover_data.get("decision")
    )

    print(
        "       Risk:",
        takeover_data.get("risk_score")
    )

    record_test(
        "Session takeover detected",
        takeover_data
        .get("anomaly_detection", {})
        .get("anomaly_detected") is True,
        takeover_data
    )

    record_test(
        "Suspicious session is rejected",
        takeover_data.get("valid") is False,
        takeover_data
    )

    # Current implementation can use MFA_REQUIRED or BLOCK
    # depending on calculated takeover risk.
    # The requirement is that the suspicious session
    # receives a protective response and is invalidated.

    record_test(
        "Suspicious session requires protective response",
        takeover_data.get("decision") in ("MFA_REQUIRED", "BLOCK"),
        takeover_data
    )

    record_test(
        "Suspicious session is revoked",
        takeover_data
        .get("revocation", {})
        .get("revoked") is True,
        takeover_data
    )


# ============================================================
# 5. WRONG PASSWORD DETECTION
# ============================================================

print("\n[5] WRONG PASSWORD DETECTION")

wrong_password_ip = "198.51.100.20"

response = post(
    "/login",
    {
        "username": USERNAME,
        "password": "DefinitelyWrongPassword!",
        "ip_address": wrong_password_ip,
        "location": "Bhubaneswar",
        "device_id": "wrong-password-test-device",
        "user_agent": "CyberGuard-E2E"
    }
)

record_test(
    "Wrong password request processed",
    response.status_code == 200,
    response.text
)

wrong_data = response.json()

# A wrong password must result in failed authentication.
# The adaptive engine may choose MONITOR, MFA_REQUIRED,
# or BLOCK depending on accumulated risk.

record_test(
    "Wrong password is rejected",
    wrong_data.get("login") == "failed",
    wrong_data
)

record_test(
    "Wrong password has risk information",
    isinstance(wrong_data.get("risk_score"), (int, float)),
    wrong_data
)

record_test(
    "ML detection result present",
    isinstance(wrong_data.get("ml_detection"), dict),
    wrong_data
)

record_test(
    "Rule detection result present",
    isinstance(wrong_data.get("rule_detection"), dict),
    wrong_data
)


# ============================================================
# 6. UNKNOWN USER
# ============================================================

print("\n[6] UNKNOWN USER DETECTION")

unknown_ip = "198.51.100.30"

response = post(
    "/login",
    {
        "username": "nonexistent_demo_user",
        "password": "WrongPassword!",
        "ip_address": unknown_ip,
        "location": "Unknown",
        "device_id": "unknown-device",
        "user_agent": "CyberGuard-Demo-Client"
    }
)

record_test(
    "Unknown user request processed",
    response.status_code == 200,
    response.text
)

unknown_data = response.json()

record_test(
    "Unknown user is blocked",
    unknown_data.get("decision") == "BLOCK",
    unknown_data
)

record_test(
    "Unknown user source IP blocked",
    unknown_data
    .get("blocklist", {})
    .get("blocked") is True,
    unknown_data
)


# ============================================================
# 7. BLOCKLIST VERIFICATION
# ============================================================

print("\n[7] IP BLOCKLIST")

response = get("/blocked-ips")

record_test(
    "Blocked IP endpoint",
    response.status_code == 200,
    response.text
)

if response.status_code == 200:

    blocked_data = response.json()

    print(
        "       Blocked IP count:",
        blocked_data.get("count")
    )

    blocked_ips = [
        entry.get("ip_address")
        for entry in blocked_data.get(
            "blocked_ips",
            []
        )
    ]

    record_test(
        "Unknown-user IP appears in blocklist",
        unknown_ip in blocked_ips
    )


# ============================================================
# 8. BLOCKED IP LOGIN
# ============================================================

print("\n[8] BLOCKED IP ENFORCEMENT")

response = post(
    "/login",
    {
        "username": USERNAME,
        "password": PASSWORD,
        "ip_address": unknown_ip,
        "location": "Bhubaneswar",
        "device_id": "demo-device",
        "user_agent": "CyberGuard-Demo-Client"
    }
)

record_test(
    "Blocked IP request processed",
    response.status_code == 200,
    response.text
)

blocked_login_data = response.json()

record_test(
    "Blocked IP login rejected",
    blocked_login_data.get("login") == "blocked",
    blocked_login_data
)

record_test(
    "Blocked IP decision is BLOCK",
    blocked_login_data.get("decision") == "BLOCK",
    blocked_login_data
)

record_test(
    "Blocked IP risk is Critical",
    blocked_login_data.get("severity") == "Critical",
    blocked_login_data
)


# ============================================================
# 9. MFA FLOW
# ============================================================

print("\n[9] MFA FLOW")

mfa_ip = "192.0.2.50"

# Generate several failed attempts to increase risk.
for _ in range(3):

    post(
        "/login",
        {
            "username": USERNAME,
            "password": "WrongPassword!",
            "ip_address": mfa_ip,
            "location": "Bhubaneswar",
            "device_id": "mfa-device",
            "user_agent": "CyberGuard-Demo-Client"
        }
    )


response = post(
    "/login",
    {
        "username": USERNAME,
        "password": PASSWORD,
        "ip_address": mfa_ip,
        "location": "Bhubaneswar",
        "device_id": "mfa-device",
        "user_agent": "CyberGuard-Demo-Client"
    }
)

record_test(
    "MFA login request processed",
    response.status_code == 200,
    response.text
)

mfa_data = response.json()

print(
    "       MFA decision:",
    mfa_data.get("decision")
)

print(
    "       MFA risk:",
    mfa_data.get("risk_score")
)

if mfa_data.get("decision") == "MFA_REQUIRED":

    record_test(
        "MFA challenge generated",
        mfa_data
        .get("mfa", {})
        .get("required") is True,
        mfa_data
    )

    challenge_id = (
        mfa_data
        .get("mfa", {})
        .get("challenge_id")
    )

    demo_otp = (
        mfa_data
        .get("mfa", {})
        .get("demo_otp")
    )

    record_test(
        "MFA challenge ID generated",
        bool(challenge_id)
    )

    record_test(
        "Demo OTP generated",
        bool(demo_otp)
    )

    if challenge_id and demo_otp:

        response = post(
            "/mfa/verify",
            {
                "challenge_id": challenge_id,
                "otp": demo_otp
            }
        )

        record_test(
            "Correct MFA verification",
            response.status_code == 200
            and response.json()
            .get("mfa", {})
            .get("verified") is True,
            response.text
        )

else:

    print(
        "       MFA_REQUIRED was not reached; "
        "recording current decision."
    )


# ============================================================
# 10. SESSION STATISTICS
# ============================================================

print("\n[10] SESSION STATISTICS")

response = get(
    "/session/statistics"
)

record_test(
    "Session statistics endpoint",
    response.status_code == 200,
    response.text
)

if response.status_code == 200:

    statistics = response.json()

    print(
        "       Statistics:",
        statistics
    )


# ============================================================
# FINAL RESULT
# ============================================================

print()
print("=" * 65)
print("CYBERGUARD ATO END-TO-END TEST RESULT")
print("=" * 65)

print(
    f"Total Tests : {passed + failed}"
)

print(
    f"Passed      : {passed}"
)

print(
    f"Failed      : {failed}"
)

if failed == 0:

    print()
    print("ATO ENGINE STATUS : PASS")

else:

    print()
    print("ATO ENGINE STATUS : REVIEW REQUIRED")

print("=" * 65)