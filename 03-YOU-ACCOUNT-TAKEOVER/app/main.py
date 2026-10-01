# ============================================================
# CYBERGUARD - ACCOUNT TAKEOVER DETECTION API
# ============================================================

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from uuid import uuid4
import json

from fastapi import FastAPI
from pydantic import BaseModel

from app.database import get_connection, initialize_database
from app.auth import verify_password

from app.history import (
    get_recent_failed_attempts,
    get_known_devices,
    get_known_ips
)

from app.rules import evaluate_login_rules

from app.risk_scoring import (
    calculate_risk,
    get_severity,
    get_decision
)

from app.blocklist import (
    block_ip,
    is_ip_blocked,
    get_block_details,
    get_blocked_ips
)

from app.response_engine import generate_response
from app.explanation import generate_explanation

# ML anomaly detection
from app.anomaly_model import predict_anomaly

# Password spraying detection
from app.password_spraying import detect_password_spraying

# MFA
from app.mfa import (
    create_mfa_challenge,
    verify_mfa_challenge
)

# Session management
from app.session_manager import (
    create_session,
    validate_session,
    detect_session_anomaly,
    update_session_activity,
    revoke_session,
    get_active_sessions,
    get_session_statistics
)


# ============================================================
# INDIA TIMEZONE
# ============================================================

IST = ZoneInfo("Asia/Kolkata")


# ============================================================
# CYBERGUARD APPLICATION
# ============================================================

app = FastAPI(
    title="CyberGuard ATO Detection API",
    description="Live Account Takeover Detection Engine",
    version="1.5.0"
)


# ============================================================
# TEMPORARY MFA CONTEXT
# ============================================================

# Stores the login context associated with an MFA challenge.
#
# Hackathon prototype only.
# Production implementation should use a secure persistent
# session/authentication store.

PENDING_MFA_CONTEXT = {}


# ============================================================
# LOGIN REQUEST MODEL
# ============================================================

class LoginRequest(BaseModel):

    username: str
    password: str

    # Controlled values supplied by the CyberGuard demo client.
    ip_address: str
    location: str
    device_id: str

    user_agent: str = "CyberGuard-Demo-Client"


# ============================================================
# MFA REQUEST MODEL
# ============================================================

class MFAVerifyRequest(BaseModel):

    challenge_id: str
    otp: str


# ============================================================
# SESSION CREATE REQUEST MODEL
# ============================================================

class SessionCreateRequest(BaseModel):

    username: str
    ip_address: str
    device_id: str
    user_agent: str = "CyberGuard-Demo-Client"
    location: str = ""


# ============================================================
# SESSION CHECK REQUEST MODEL
# ============================================================

class SessionCheckRequest(BaseModel):

    session_id: str

    current_ip: str
    current_device_id: str

    current_user_agent: str = (
        "CyberGuard-Demo-Client"
    )

    current_location: str = ""


# ============================================================
# SESSION REVOKE REQUEST MODEL
# ============================================================

class SessionRevokeRequest(BaseModel):

    session_id: str

    reason: str = (
        "Session revoked by CyberGuard"
    )


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():

    initialize_database()


# ============================================================
# HOME
# ============================================================

@app.get("/")
def root():

    return {
        "system": "CyberGuard",
        "module": "Account Takeover Detection",
        "status": "online",

        "ml_detection": "enabled",
        "password_spraying_detection": "enabled",
        "ip_blocklist": "enabled",
        "mfa": "enabled",
        "session_management": "enabled",
        "session_takeover_detection": "enabled"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "ml_model": "enabled",
        "password_spraying_detection": "enabled",
        "ip_blocklist": "enabled",
        "mfa": "enabled",
        "session_management": "enabled",
        "session_takeover_detection": "enabled"
    }


# ============================================================
# BLOCKED IPs
# ============================================================

@app.get("/blocked-ips")
def blocked_ips():

    blocked = get_blocked_ips()

    return {
        "count": len(blocked),
        "blocked_ips": blocked
    }


# ============================================================
# SESSION LIST
# ============================================================

@app.get("/sessions")
def sessions():

    active_sessions = get_active_sessions()

    return {
        "count": len(active_sessions),
        "sessions": active_sessions
    }


# ============================================================
# SESSION STATISTICS
# ============================================================

@app.get("/session/statistics")
def session_statistics():

    return get_session_statistics()


# ============================================================
# LOCATION NORMALIZATION
# ============================================================

def normalize_location(location):
    """
    Normalize location values before comparison.

    Empty or unavailable locations are represented by an
    empty string.

    VMware private IP addresses do not provide reliable
    geographic information, therefore Unknown must not
    be interpreted as a new geographic location.
    """

    if location is None:
        return ""

    normalized = str(
        location
    ).strip().lower()

    if normalized in {
        "",
        "unknown",
        "unknown location",
        "unavailable",
        "n/a",
        "na",
        "none"
    }:
        return ""

    return normalized


# ============================================================
# HELPER — RUN ML ANOMALY DETECTION
# ============================================================

def run_ml_detection(
    user,
    request,
    now,
    failed_attempts,
    is_new_ip,
    is_new_device
):

    """
    Build the feature vector required by the trained
    Isolation Forest model and perform anomaly detection.
    """

    # --------------------------------------------------------
    # GET USER HOME LOCATION SAFELY
    # --------------------------------------------------------

    try:

        home_location = user["home_location"]

    except (
        KeyError,
        IndexError,
        TypeError
    ):

        home_location = ""

    if home_location is None:

        home_location = ""


    # --------------------------------------------------------
    # DETECT NEW LOCATION
    # --------------------------------------------------------

    login_location = normalize_location(
        request.location
    )

    normalized_home_location = normalize_location(
        home_location
    )


    # --------------------------------------------------------
    # UNKNOWN LOCATION
    # --------------------------------------------------------

    if not login_location:

        is_new_location = False


    # --------------------------------------------------------
    # KNOWN LOCATION AVAILABLE
    # --------------------------------------------------------

    elif normalized_home_location:

        is_new_location = (
            login_location
            != normalized_home_location
        )


    # --------------------------------------------------------
    # NO HOME LOCATION AVAILABLE
    # --------------------------------------------------------

    else:

        is_new_location = False


    # --------------------------------------------------------
    # ML FEATURE VECTOR
    # --------------------------------------------------------

    ml_features = {

        "login_hour": int(
            now.hour
        ),

        "failed_attempts": int(
            failed_attempts
        ),

        "new_ip": int(
            is_new_ip
        ),

        "new_device": int(
            is_new_device
        ),

        "new_location": int(
            is_new_location
        ),

        # Prototype value.
        "login_frequency": 1,

        # Session has just started.
        "session_duration": 0,

        # No post-login actions yet.
        "actions_count": 0
    }


    # --------------------------------------------------------
    # RUN ISOLATION FOREST
    # --------------------------------------------------------

    ml_result = predict_anomaly(
        ml_features
    )


    # --------------------------------------------------------
    # NORMALIZE NUMPY TYPES
    # --------------------------------------------------------

    ml_result = {

        "prediction": int(
            ml_result["prediction"]
        ),

        "raw_score": float(
            ml_result["raw_score"]
        ),

        "ml_risk_score": int(
            ml_result["ml_risk_score"]
        ),

        "anomalous": bool(
            ml_result["anomalous"]
        )
    }


    return (
        ml_result,
        ml_features,
        is_new_location
    )


# ============================================================
# HELPER — PASSWORD SPRAYING DETECTION
# ============================================================

def run_password_spraying_detection(
    ip_address
):

    result = detect_password_spraying(
        ip_address=ip_address,
        minutes=10,
        username_threshold=3,
        attempt_threshold=5
    )

    return {

        "ip_address": str(
            result["ip_address"]
        ),

        "failed_attempts": int(
            result["failed_attempts"]
        ),

        "targeted_users": int(
            result["targeted_users"]
        ),

        "spraying_detected": bool(
            result["spraying_detected"]
        )
    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/login")
def login(request: LoginRequest):

    # ========================================================
    # GENERATE EVENT ID
    # ========================================================

    event_id = (
        f"ATO-{uuid4().hex[:8].upper()}"
    )


    # ========================================================
    # INDIA STANDARD TIME
    # ========================================================

    now = datetime.now(
        IST
    )

    timestamp = now.isoformat()


    # ========================================================
    # CHECK IP BLOCKLIST FIRST
    # ========================================================

    if is_ip_blocked(
        request.ip_address
    ):

        block_details = get_block_details(
            request.ip_address
        )

        indicators = [
            "Source IP is currently blocked by CyberGuard"
        ]

        return {

            "event_id": event_id,

            "threat_type":
                "account_takeover",

            "login":
                "blocked",

            "risk_score":
                100,

            "severity":
                "Critical",

            "decision":
                "BLOCK",

            "blocklist": {

                "blocked":
                    True,

                "details":
                    block_details
            },

            "indicators":
                indicators,

            "explanation": (
                "The login request was rejected because "
                "the source IP address is currently blocked "
                "by the CyberGuard temporary blocklist."
            ),

            "recommended_actions": [

                "Reject the authentication request",

                "Maintain temporary source IP block",

                "Review security events associated with the IP",

                "Investigate possible account takeover activity"
            ]
        }


    # ========================================================
    # DATABASE CONNECTION
    # ========================================================

    connection = get_connection()
    cursor = connection.cursor()


    # ========================================================
    # FIND USER
    # ========================================================

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (
            request.username,
        )
    )

    user = cursor.fetchone()


    # ========================================================
    # UNKNOWN USER
    # ========================================================

    if not user:

        indicators = [

            "Unknown username",

            "Authentication attempt against a non-existent account"
        ]


        spray_result = (
            run_password_spraying_detection(
                request.ip_address
            )
        )


        if spray_result[
            "spraying_detected"
        ]:

            indicators.append(
                "Password spraying attack detected from source IP"
            )


        risk_score = 100
        severity = "Critical"
        decision = "BLOCK"


        # ----------------------------------------------------
        # BLOCK SOURCE IP
        # ----------------------------------------------------

        block_details = block_ip(

            ip_address=
                request.ip_address,

            reason=
                "Unknown account authentication attempt",

            duration_minutes=
                15
        )


        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        recommended_actions = (
            generate_response(
                decision
            )
        )


        # ----------------------------------------------------
        # EXPLANATION
        # ----------------------------------------------------

        explanation = generate_explanation(

            username=
                request.username,

            risk_score=
                risk_score,

            severity=
                severity,

            indicators=
                indicators
        )


        # ----------------------------------------------------
        # SAVE EVENT
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO login_events (
                event_id,
                username,
                timestamp,
                ip_address,
                location,
                device_id,
                status,
                risk_score,
                severity,
                decision,
                indicators
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,

                request.username,

                timestamp,

                request.ip_address,

                request.location,

                request.device_id,

                "failed",

                risk_score,

                severity,

                decision,

                json.dumps(
                    indicators
                )
            )
        )

        connection.commit()
        connection.close()


        return {

            "event_id":
                event_id,

            "threat_type":
                "account_takeover",

            "login":
                "failed",

            "risk_score":
                risk_score,

            "severity":
                severity,

            "decision":
                decision,

            "ml_detection": {

                "prediction":
                    -1,

                "anomalous":
                    True,

                "ml_risk_score":
                    100,

                "status":
                    "unknown_user"
            },

            "password_spraying":
                spray_result,

            "blocklist": {

                "blocked":
                    True,

                "details":
                    block_details
            },

            "indicators":
                indicators,

            "explanation":
                explanation,

            "recommended_actions":
                recommended_actions
        }


    # ========================================================
    # USER EXISTS
    # ========================================================

    # --------------------------------------------------------
    # GET USER HISTORY
    # --------------------------------------------------------

    recent_failed_attempts = (
        get_recent_failed_attempts(
            request.username,
            minutes=10
        )
    )

    known_devices = (
        get_known_devices(
            request.username
        )
    )

    known_ips = (
        get_known_ips(
            request.username
        )
    )


    # --------------------------------------------------------
    # NEW DEVICE
    # --------------------------------------------------------

    is_new_device = (
        request.device_id
        not in known_devices
    )


    # --------------------------------------------------------
    # NEW IP
    # --------------------------------------------------------

    is_new_ip = (
        request.ip_address
        not in known_ips
    )


    # --------------------------------------------------------
    # PASSWORD SPRAYING
    # --------------------------------------------------------

    spray_result = (
        run_password_spraying_detection(
            request.ip_address
        )
    )


    # ========================================================
    # VERIFY PASSWORD
    # ========================================================

    password_valid = verify_password(
        request.password,
        user["password"]
    )


    # ========================================================
    # WRONG PASSWORD
    # ========================================================

    if not password_valid:

        failed_attempts = (
            recent_failed_attempts + 1
        )


        # ----------------------------------------------------
        # RULE ENGINE
        # ----------------------------------------------------

        rule_score, indicators = (
            evaluate_login_rules(

                user=user,

                ip_address=
                    request.ip_address,

                location=
                    request.location,

                device_id=
                    request.device_id,

                timestamp=
                    now,

                failed_attempts=
                    failed_attempts,

                is_new_device=
                    is_new_device,

                is_new_ip=
                    is_new_ip
            )
        )


        # ----------------------------------------------------
        # CREDENTIAL ATTACK INDICATOR
        # ----------------------------------------------------

        if failed_attempts >= 5:

            indicators.append(
                "Possible credential attack detected"
            )

            rule_score += 10

            rule_score = min(
                rule_score,
                100
            )


        # ----------------------------------------------------
        # PASSWORD SPRAYING
        # ----------------------------------------------------

        if spray_result[
            "spraying_detected"
        ]:

            indicators.append(
                "Password spraying attack detected from source IP"
            )

            rule_score += 20

            rule_score = min(
                rule_score,
                100
            )


        # ----------------------------------------------------
        # ML DETECTION
        # ----------------------------------------------------

        (
            ml_result,
            ml_features,
            is_new_location
        ) = run_ml_detection(

            user=user,

            request=request,

            now=now,

            failed_attempts=
                failed_attempts,

            is_new_ip=
                is_new_ip,

            is_new_device=
                is_new_device
        )


        ml_score = (
            ml_result["ml_risk_score"]
        )


        # ----------------------------------------------------
        # ML INDICATOR
        # ----------------------------------------------------

        if ml_result[
            "anomalous"
        ]:

            indicators.append(
                "AI anomaly model detected abnormal login behavior"
            )


        # ----------------------------------------------------
        # LOCATION INDICATOR
        # ----------------------------------------------------

        if is_new_location:

            indicators.append(
                "Login location differs from the user's normal location"
            )


        # ----------------------------------------------------
        # FINAL RISK
        # ----------------------------------------------------

        risk_score = calculate_risk(

            rule_score=
                rule_score,

            ml_score=
                ml_score
        )


        # ----------------------------------------------------
        # SEVERITY
        # ----------------------------------------------------

        severity = get_severity(
            risk_score
        )


        # ----------------------------------------------------
        # DECISION
        # ----------------------------------------------------

        decision = get_decision(
            risk_score
        )


        # ----------------------------------------------------
        # BLOCK IF REQUIRED
        # ----------------------------------------------------

        block_details = None

        if decision == "BLOCK":

            block_reason = (
                "High-risk account takeover attempt"
            )

            if spray_result[
                "spraying_detected"
            ]:

                block_reason = (
                    "Password spraying detected"
                )


            block_details = block_ip(

                ip_address=
                    request.ip_address,

                reason=
                    block_reason,

                duration_minutes=
                    15
            )


            indicators.append(
                "Source IP temporarily blocked by CyberGuard"
            )


        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        recommended_actions = (
            generate_response(
                decision
            )
        )


        # ----------------------------------------------------
        # EXPLANATION
        # ----------------------------------------------------

        explanation = (
            generate_explanation(

                username=
                    request.username,

                risk_score=
                    risk_score,

                severity=
                    severity,

                indicators=
                    indicators
            )
        )


        # ----------------------------------------------------
        # SAVE EVENT
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO login_events (
                event_id,
                user_id,
                username,
                timestamp,
                ip_address,
                location,
                device_id,
                status,
                risk_score,
                severity,
                decision,
                indicators
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,

                user["user_id"],

                request.username,

                timestamp,

                request.ip_address,

                request.location,

                request.device_id,

                "failed",

                risk_score,

                severity,

                decision,

                json.dumps(
                    indicators
                )
            )
        )


        connection.commit()
        connection.close()


        return {

            "event_id":
                event_id,

            "threat_type":
                "account_takeover",

            "login":
                "failed",

            "risk_score":
                risk_score,

            "severity":
                severity,

            "decision":
                decision,

            "failed_attempts_last_10_minutes":
                failed_attempts,

            "new_ip":
                is_new_ip,

            "new_device":
                is_new_device,

            "new_location":
                is_new_location,

            "rule_detection": {

                "rule_risk_score":
                    rule_score
            },

            "ml_detection": {

                "prediction":
                    ml_result["prediction"],

                "anomalous":
                    ml_result["anomalous"],

                "raw_score":
                    ml_result["raw_score"],

                "ml_risk_score":
                    ml_score
            },

            "password_spraying":
                spray_result,

            "blocklist": {

                "blocked":
                    decision == "BLOCK",

                "details":
                    block_details
            },

            "ml_features":
                ml_features,

            "indicators":
                indicators,

            "explanation":
                explanation,

            "recommended_actions":
                recommended_actions
        }


    # ========================================================
    # CORRECT PASSWORD
    # ========================================================

    # --------------------------------------------------------
    # RULE ENGINE
    # --------------------------------------------------------

    rule_score, indicators = (
        evaluate_login_rules(

            user=user,

            ip_address=
                request.ip_address,

            location=
                request.location,

            device_id=
                request.device_id,

            timestamp=
                now,

            failed_attempts=
                recent_failed_attempts,

            is_new_device=
                is_new_device,

            is_new_ip=
                is_new_ip
        )
    )


    # --------------------------------------------------------
    # FAILED LOGIN HISTORY
    # --------------------------------------------------------

    if recent_failed_attempts >= 3:

        indicators.append(

            f"{recent_failed_attempts} failed login attempts "
            "were detected before this successful login"
        )


    # --------------------------------------------------------
    # PASSWORD SPRAYING
    # --------------------------------------------------------

    if spray_result[
        "spraying_detected"
    ]:

        indicators.append(
            "Password spraying attack detected from source IP"
        )

        rule_score += 20

        rule_score = min(
            rule_score,
            100
        )


    # --------------------------------------------------------
    # ML DETECTION
    # --------------------------------------------------------

    (
        ml_result,
        ml_features,
        is_new_location
    ) = run_ml_detection(

        user=user,

        request=request,

        now=now,

        failed_attempts=
            recent_failed_attempts,

        is_new_ip=
            is_new_ip,

        is_new_device=
            is_new_device
    )


    ml_score = (
        ml_result["ml_risk_score"]
    )


    # --------------------------------------------------------
    # ML INDICATOR
    # --------------------------------------------------------

    if ml_result[
        "anomalous"
    ]:

        indicators.append(
            "AI anomaly model detected abnormal login behavior"
        )


    # --------------------------------------------------------
    # LOCATION INDICATOR
    # --------------------------------------------------------

    if is_new_location:

        indicators.append(
            "Login location differs from the user's normal location"
        )


    # --------------------------------------------------------
    # FINAL RISK
    # --------------------------------------------------------

    risk_score = calculate_risk(

        rule_score=
            rule_score,

        ml_score=
            ml_score
    )


    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    severity = get_severity(
        risk_score
    )


    # --------------------------------------------------------
    # DECISION
    # --------------------------------------------------------

    decision = get_decision(
        risk_score
    )


    # ========================================================
    # ADAPTIVE MFA
    # ========================================================

    # A new device or IP should not silently authenticate
    # even when the numerical risk score is only ALLOW/MONITOR.

    new_authentication_context = (

        is_new_device

        or is_new_ip

        or is_new_location
    )


    if (
        decision in {
            "ALLOW",
            "MONITOR"
        }

        and new_authentication_context
    ):

        decision = "MFA_REQUIRED"

        indicators.append(
            "Adaptive MFA triggered because the authentication "
            "context is new (new device, IP address, or location)"
        )


    # ========================================================
    # MFA REQUIRED
    # ========================================================

    if decision == "MFA_REQUIRED":

        # ----------------------------------------------------
        # CREATE MFA CHALLENGE
        # ----------------------------------------------------

        mfa_challenge = (
            create_mfa_challenge(

                username=
                    request.username,

                validity_minutes=
                    5
            )
        )


        # ----------------------------------------------------
        # STORE AUTHENTICATION CONTEXT
        # ----------------------------------------------------

        PENDING_MFA_CONTEXT[
            mfa_challenge["challenge_id"]
        ] = {

            "username":
                request.username,

            "ip_address":
                request.ip_address,

            "device_id":
                request.device_id,

            "user_agent":
                request.user_agent,

            "location":
                request.location,

            "event_id":
                event_id
        }


        # ----------------------------------------------------
        # MFA INDICATOR
        # ----------------------------------------------------

        indicators.append(
            "Additional MFA verification required due to elevated risk"
        )


        # ----------------------------------------------------
        # RESPONSE ACTIONS
        # ----------------------------------------------------

        recommended_actions = (
            generate_response(
                decision
            )
        )


        # ----------------------------------------------------
        # EXPLANATION
        # ----------------------------------------------------

        explanation = (
            generate_explanation(

                username=
                    request.username,

                risk_score=
                    risk_score,

                severity=
                    severity,

                indicators=
                    indicators
            )
        )


        # ----------------------------------------------------
        # SAVE MFA PENDING EVENT
        # ----------------------------------------------------

        cursor.execute(
            """
            INSERT INTO login_events (
                event_id,
                user_id,
                username,
                timestamp,
                ip_address,
                location,
                device_id,
                status,
                risk_score,
                severity,
                decision,
                indicators
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,

                user["user_id"],

                request.username,

                timestamp,

                request.ip_address,

                request.location,

                request.device_id,

                "mfa_pending",

                risk_score,

                severity,

                decision,

                json.dumps(
                    indicators
                )
            )
        )


        connection.commit()
        connection.close()


        # ----------------------------------------------------
        # RETURN MFA CHALLENGE
        # ----------------------------------------------------

        return {

            "event_id":
                event_id,

            "threat_type":
                "account_takeover",

            "login":
                "mfa_required",

            "risk_score":
                risk_score,

            "severity":
                severity,

            "decision":
                "MFA_REQUIRED",

            "failed_attempts_last_10_minutes":
                recent_failed_attempts,

            "new_ip":
                is_new_ip,

            "new_device":
                is_new_device,

            "new_location":
                is_new_location,

            "rule_detection": {

                "rule_risk_score":
                    rule_score
            },

            "ml_detection": {

                "prediction":
                    ml_result["prediction"],

                "anomalous":
                    ml_result["anomalous"],

                "raw_score":
                    ml_result["raw_score"],

                "ml_risk_score":
                    ml_score
            },

            "password_spraying":
                spray_result,

            "blocklist": {

                "blocked":
                    False,

                "details":
                    None
            },

            "ml_features":
                ml_features,

            "mfa": {

                "required":
                    True,

                "challenge_id":
                    mfa_challenge["challenge_id"],

                # Demonstration only.
                "demo_otp":
                    mfa_challenge["otp"],

                "expires_at":
                    mfa_challenge["expires_at"]
            },

            "indicators":
                indicators,

            "explanation":
                explanation,

            "recommended_actions":
                recommended_actions
        }


    # ========================================================
    # BLOCK
    # ========================================================

    block_details = None

    if decision == "BLOCK":

        block_reason = (
            "High-risk successful authentication attempt"
        )


        if spray_result[
            "spraying_detected"
        ]:

            block_reason = (
                "Password spraying detected"
            )


        block_details = block_ip(

            ip_address=
                request.ip_address,

            reason=
                block_reason,

            duration_minutes=
                15
        )


        indicators.append(
            "Source IP temporarily blocked by CyberGuard"
        )


    # ========================================================
    # RESPONSE ACTIONS
    # ========================================================

    recommended_actions = (
        generate_response(
            decision
        )
    )


    # ========================================================
    # EXPLANATION
    # ========================================================

    explanation = (
        generate_explanation(

            username=
                request.username,

            risk_score=
                risk_score,

            severity=
                severity,

            indicators=
                indicators
        )
    )


    # ========================================================
    # LOGIN STATUS
    # ========================================================

    if decision == "BLOCK":

        login_status = "blocked"

    else:

        login_status = "successful"


    # ========================================================
    # SAVE LOGIN EVENT
    # ========================================================

    cursor.execute(
        """
        INSERT INTO login_events (
            event_id,
            user_id,
            username,
            timestamp,
            ip_address,
            location,
            device_id,
            status,
            risk_score,
            severity,
            decision,
            indicators
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,

            user["user_id"],

            request.username,

            timestamp,

            request.ip_address,

            request.location,

            request.device_id,

            (
                "success"
                if decision != "BLOCK"
                else "blocked"
            ),

            risk_score,

            severity,

            decision,

            json.dumps(
                indicators
            )
        )
    )


    connection.commit()
    connection.close()


    # ========================================================
    # CREATE NORMAL SESSION
    # ========================================================

    session_data = None


    if decision == "ALLOW":

        session_data = create_session(

            username=
                request.username,

            ip_address=
                request.ip_address,

            device_id=
                request.device_id,

            user_agent=
                request.user_agent,

            location=
                request.location
        )


    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    response = {

        "event_id":
            event_id,

        "threat_type":
            "account_takeover",

        "login":
            login_status,

        "risk_score":
            risk_score,

        "severity":
            severity,

        "decision":
            decision,

        "failed_attempts_last_10_minutes":
            recent_failed_attempts,

        "new_ip":
            is_new_ip,

        "new_device":
            is_new_device,

        "new_location":
            is_new_location,

        "rule_detection": {

            "rule_risk_score":
                rule_score
        },

        "ml_detection": {

            "prediction":
                ml_result["prediction"],

            "anomalous":
                ml_result["anomalous"],

            "raw_score":
                ml_result["raw_score"],

            "ml_risk_score":
                ml_score
        },

        "password_spraying":
            spray_result,

        "blocklist": {

            "blocked":
                decision == "BLOCK",

            "details":
                block_details
        },

        "ml_features":
            ml_features,

        "indicators":
            indicators,

        "explanation":
            explanation,

        "recommended_actions":
            recommended_actions
    }


    # ========================================================
    # ATTACH SESSION
    # ========================================================

    if session_data:

        response["session"] = {

            "created":
                True,

            "session_id":
                session_data["session_id"],

            "username":
                session_data["username"],

            "status":
                session_data["status"],

            "created_at":
                session_data["created_at"],

            "expires_at":
                session_data["expires_at"],

            "absolute_expires_at":
                session_data[
                    "absolute_expires_at"
                ]
        }

    else:

        response["session"] = {

            "created":
                False,

            "reason": (
                "Session was not created because "
                "authentication did not result in ALLOW"
            )
        }


    return response


# ============================================================
# MFA VERIFICATION
# ============================================================

@app.post("/mfa/verify")
def verify_mfa(
    request: MFAVerifyRequest
):

    # --------------------------------------------------------
    # VERIFY MFA CHALLENGE
    # --------------------------------------------------------

    result = verify_mfa_challenge(

        challenge_id=
            request.challenge_id,

        otp=
            request.otp
    )


    # --------------------------------------------------------
    # MFA FAILED
    # --------------------------------------------------------

    if not result["verified"]:

        return {

            "login":
                "rejected",

            "mfa": {

                "verified":
                    False,

                "challenge_id":
                    request.challenge_id
            },

            "decision":
                "BLOCK",

            "severity":
                "High",

            "reason":
                result["reason"],

            "recommended_actions": [

                "Reject authentication",

                "Require a new MFA challenge",

                "Review repeated MFA failures"
            ]
        }


    # --------------------------------------------------------
    # GET STORED LOGIN CONTEXT
    # --------------------------------------------------------

    mfa_context = (
        PENDING_MFA_CONTEXT.pop(
            request.challenge_id,
            None
        )
    )


    # --------------------------------------------------------
    # MARK MFA LOGIN SUCCESSFUL
    # --------------------------------------------------------

    if mfa_context:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE login_events
            SET status = 'success'
            WHERE event_id = ?
              AND username = ?
              AND status = 'mfa_pending'
            """,
            (
                mfa_context["event_id"],
                mfa_context["username"]
            )
        )

        connection.commit()
        connection.close()


    # --------------------------------------------------------
    # CREATE AUTHENTICATED SESSION
    # --------------------------------------------------------

    session_data = None


    if mfa_context:

        session_data = create_session(

            username=
                mfa_context["username"],

            ip_address=
                mfa_context["ip_address"],

            device_id=
                mfa_context["device_id"],

            user_agent=
                mfa_context["user_agent"],

            location=
                mfa_context["location"]
        )


    # --------------------------------------------------------
    # MFA SUCCESS
    # --------------------------------------------------------

    response = {

        "login":
            "successful",

        "mfa": {

            "verified":
                True,

            "challenge_id":
                result["challenge_id"]
        },

        "username":
            result["username"],

        "decision":
            "ALLOW",

        "message": (
            "MFA verification successful. "
            "Authentication may proceed."
        ),

        "recommended_actions": [

            "Allow authenticated session",

            "Record successful MFA verification",

            "Continue normal session monitoring"
        ]
    }


    # --------------------------------------------------------
    # SESSION INFORMATION
    # --------------------------------------------------------

    if session_data:

        response["session"] = {

            "created":
                True,

            "session_id":
                session_data["session_id"],

            "username":
                session_data["username"],

            "status":
                session_data["status"],

            "created_at":
                session_data["created_at"],

            "expires_at":
                session_data["expires_at"],

            "absolute_expires_at":
                session_data[
                    "absolute_expires_at"
                ]
        }

    else:

        response["session"] = {

            "created":
                False,

            "reason": (
                "MFA succeeded but the original "
                "login context was unavailable."
            )
        }


    return response


# ============================================================
# SESSION CREATE
# ============================================================

@app.post("/session/create")
def session_create(
    request: SessionCreateRequest
):

    session = create_session(

        username=
            request.username,

        ip_address=
            request.ip_address,

        device_id=
            request.device_id,

        user_agent=
            request.user_agent,

        location=
            request.location
    )


    return {

        "session":
            "created",

        "session_details":
            session
    }


# ============================================================
# SESSION CHECK
# ============================================================

@app.post("/session/check")
def session_check(
    request: SessionCheckRequest
):

    # --------------------------------------------------------
    # VALIDATE SESSION
    # --------------------------------------------------------

    validation = validate_session(
        request.session_id
    )


    if not validation["valid"]:

        return {

            "session":
                "invalid",

            "valid":
                False,

            "decision":
                "BLOCK",

            "severity":
                "High",

            "validation":
                validation,

            "recommended_actions": [

                "Reject session request",

                "Require authentication again",

                "Investigate invalid session activity"
            ]
        }


    # --------------------------------------------------------
    # DETECT SESSION ANOMALY
    # --------------------------------------------------------

    anomaly_result = detect_session_anomaly(

        session_id=
            request.session_id,

        ip_address=
            request.current_ip,

        device_id=
            request.current_device_id,

        user_agent=
            request.current_user_agent,

        location=
            request.current_location
    )


    # --------------------------------------------------------
    # SUSPICIOUS SESSION
    # --------------------------------------------------------

    if anomaly_result[
        "anomaly_detected"
    ]:

        # ----------------------------------------------------
        # REVOKE SESSION
        # ----------------------------------------------------

        revoke_result = revoke_session(

            session_id=
                request.session_id,

            reason=
                "Possible session takeover detected"
        )


        return {

            "session":
                "suspicious",

            "valid":
                False,

            "username":
                anomaly_result.get(
                    "username",
                    validation.get(
                        "username"
                    )
                ),

            "session_id":
                request.session_id,

            "anomaly_detection":
                anomaly_result,

            "revocation":
                revoke_result,

            "decision":
                anomaly_result[
                    "decision"
                ],

            "severity":
                anomaly_result[
                    "severity"
                ],

            "risk_score":
                anomaly_result[
                    "risk_score"
                ],

            "recommended_actions": [

                "Reject current session request",

                "Revoke suspicious session",

                "Require re-authentication",

                "Require MFA if appropriate",

                "Investigate possible session hijacking"
            ]
        }


    # --------------------------------------------------------
    # NORMAL SESSION
    # --------------------------------------------------------

    activity = update_session_activity(
        request.session_id
    )


    return {

        "session":
            "valid",

        "valid":
            True,

        "username":
            anomaly_result.get(
                "username",
                validation.get(
                    "username"
                )
            ),

        "session_id":
            request.session_id,

        "anomaly_detection":
            anomaly_result,

        "activity":
            activity,

        "decision":
            "ALLOW",

        "severity":
            "Low",

        "risk_score":
            0,

        "recommended_actions": [

            "Allow session request",

            "Continue session monitoring"
        ]
    }


# ============================================================
# SESSION REVOKE
# ============================================================

@app.post("/session/revoke")
def session_revoke(
    request: SessionRevokeRequest
):

    result = revoke_session(

        session_id=
            request.session_id,

        reason=
            request.reason
    )


    if result["revoked"]:

        return {

            "session":
                "revoked",

            "decision":
                "BLOCK",

            "severity":
                "High",

            "result":
                result,

            "recommended_actions": [

                "Terminate session access",

                "Require re-authentication",

                "Review associated security events"
            ]
        }


    return {

        "session":
            "not_revoked",

        "decision":
            "BLOCK",

        "severity":
            "High",

        "result":
            result,

        "recommended_actions": [

            "Verify the session identifier",

            "Review session state"
        ]
    }


# ============================================================
# END OF CYBERGUARD ATO API
# ============================================================