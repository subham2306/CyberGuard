"""
CyberGuard - Session Management & Session Takeover Detection

Purpose:
    Manage authenticated sessions and detect possible session hijacking /
    session takeover using behavioral and client-property changes.

This is a hackathon prototype implementation.
For production, session storage should be moved from memory to a secure
persistent/session store such as Redis or a protected database.
"""

from datetime import datetime, timezone, timedelta
import secrets


# ============================================================
# CONFIGURATION
# ============================================================

# Idle timeout:
# Session becomes invalid if there is no activity for this duration.
IDLE_TIMEOUT_MINUTES = 30

# Absolute timeout:
# Session becomes invalid regardless of activity after this duration.
ABSOLUTE_TIMEOUT_HOURS = 8

# Risk thresholds
RISK_MONITOR = 30
RISK_MFA = 60
RISK_BLOCK = 80


# ============================================================
# IN-MEMORY SESSION STORE
# ============================================================

ACTIVE_SESSIONS = {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _utc_now():
    """
    Return current UTC time as timezone-aware datetime.
    """
    return datetime.now(timezone.utc)


def _parse_datetime(value):
    """
    Convert ISO timestamp string into timezone-aware datetime.
    """
    if isinstance(value, datetime):
        return value

    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def _generate_session_id():
    """
    Generate a cryptographically secure session identifier.

    secrets.token_urlsafe(32) provides a high-entropy unpredictable
    session identifier suitable for this prototype.
    """
    return secrets.token_urlsafe(32)


def _get_severity(risk_score):
    """
    Convert risk score into CyberGuard severity.
    """

    if risk_score >= RISK_BLOCK:
        return "Critical"

    if risk_score >= RISK_MFA:
        return "High"

    if risk_score >= RISK_MONITOR:
        return "Medium"

    return "Low"


def _get_decision(risk_score):
    """
    Convert risk score into CyberGuard response decision.
    """

    if risk_score >= RISK_BLOCK:
        return "BLOCK"

    if risk_score >= RISK_MFA:
        return "MFA_REQUIRED"

    if risk_score >= RISK_MONITOR:
        return "MONITOR"

    return "ALLOW"


# ============================================================
# SESSION CREATION
# ============================================================

def create_session(
    username: str,
    ip_address: str,
    device_id: str = "",
    user_agent: str = "",
    location: str = "",
    idle_timeout_minutes: int = IDLE_TIMEOUT_MINUTES,
    absolute_timeout_hours: int = ABSOLUTE_TIMEOUT_HOURS
):
    """
    Create a new authenticated session.

    Parameters:
        username:
            Authenticated username.

        ip_address:
            Source IP address.

        device_id:
            Device identifier supplied by the application/demo.

        user_agent:
            Browser/client User-Agent.

        location:
            Login location.

        idle_timeout_minutes:
            Maximum inactivity period.

        absolute_timeout_hours:
            Maximum total lifetime.

    Returns:
        Dictionary containing session details.
    """

    now = _utc_now()

    session_id = _generate_session_id()

    idle_expires_at = now + timedelta(
        minutes=idle_timeout_minutes
    )

    absolute_expires_at = now + timedelta(
        hours=absolute_timeout_hours
    )

    session = {
        "session_id": session_id,
        "username": username,

        # Client binding information
        "ip_address": ip_address,
        "device_id": device_id,
        "user_agent": user_agent,
        "location": location,

        # Session lifecycle
        "created_at": now.isoformat(),
        "last_activity": now.isoformat(),
        "expires_at": idle_expires_at.isoformat(),
        "absolute_expires_at": absolute_expires_at.isoformat(),

        # Session state
        "status": "active",

        # Monitoring
        "last_risk_score": 0,
        "last_decision": "ALLOW",
        "anomaly_count": 0
    }

    ACTIVE_SESSIONS[session_id] = session

    return session.copy()


# ============================================================
# SESSION LOOKUP
# ============================================================

def get_session(session_id: str):
    """
    Retrieve a session by session ID.

    Returns:
        Session dictionary or None.
    """

    session = ACTIVE_SESSIONS.get(session_id)

    if not session:
        return None

    return session.copy()


# ============================================================
# SESSION VALIDATION
# ============================================================

def validate_session(session_id: str):
    """
    Validate whether a session is currently active.

    Checks:
        1. Session exists
        2. Session status
        3. Idle timeout
        4. Absolute timeout

    Returns:
        Structured validation result.
    """

    session = ACTIVE_SESSIONS.get(session_id)

    if not session:
        return {
            "valid": False,
            "reason": "Invalid or unknown session"
        }

    if session["status"] != "active":
        return {
            "valid": False,
            "reason": f"Session status is {session['status']}"
        }

    now = _utc_now()

    last_activity = _parse_datetime(
        session["last_activity"]
    )

    expires_at = _parse_datetime(
        session["expires_at"]
    )

    absolute_expires_at = _parse_datetime(
        session["absolute_expires_at"]
    )

    # --------------------------------------------------------
    # Absolute expiration
    # --------------------------------------------------------

    if now >= absolute_expires_at:

        session["status"] = "expired"

        return {
            "valid": False,
            "reason": "Session absolute timeout expired",
            "session_id": session_id
        }

    # --------------------------------------------------------
    # Idle expiration
    # --------------------------------------------------------

    if now >= expires_at:

        session["status"] = "expired"

        return {
            "valid": False,
            "reason": "Session idle timeout expired",
            "session_id": session_id
        }

    # --------------------------------------------------------
    # Valid session
    # --------------------------------------------------------

    return {
        "valid": True,
        "reason": "Session is valid",
        "session_id": session_id,
        "username": session["username"],
        "status": session["status"],
        "last_activity": session["last_activity"],
        "expires_at": session["expires_at"],
        "absolute_expires_at": session["absolute_expires_at"]
    }


# ============================================================
# SESSION ACTIVITY UPDATE
# ============================================================

def update_session_activity(session_id: str):
    """
    Update session activity and extend idle expiration.

    Absolute expiration is NOT extended.
    """

    session = ACTIVE_SESSIONS.get(session_id)

    if not session:
        return {
            "updated": False,
            "reason": "Invalid or unknown session"
        }

    validation = validate_session(session_id)

    if not validation["valid"]:
        return {
            "updated": False,
            "reason": validation["reason"]
        }

    now = _utc_now()

    new_idle_expiration = now + timedelta(
        minutes=IDLE_TIMEOUT_MINUTES
    )

    absolute_expiration = _parse_datetime(
        session["absolute_expires_at"]
    )

    # Never allow idle expiration to go beyond absolute expiration
    if new_idle_expiration > absolute_expiration:
        new_idle_expiration = absolute_expiration

    session["last_activity"] = now.isoformat()

    session["expires_at"] = (
        new_idle_expiration.isoformat()
    )

    return {
        "updated": True,
        "session_id": session_id,
        "last_activity": session["last_activity"],
        "expires_at": session["expires_at"]
    }


# ============================================================
# SESSION TAKEOVER / HIJACKING DETECTION
# ============================================================

def detect_session_anomaly(
    session_id: str,
    ip_address: str,
    device_id: str = "",
    user_agent: str = "",
    location: str = ""
):
    """
    Detect suspicious changes in an established session.

    Detection indicators:

        IP address change:
            +30

        Device change:
            +30

        User-Agent change:
            +15

        Location change:
            +25

    Multiple indicators increase confidence that the session may
    have been stolen or hijacked.

    Important:
        A changed IP address alone does NOT automatically mean
        account takeover. The system combines multiple indicators.
    """

    session = ACTIVE_SESSIONS.get(session_id)

    if not session:
        return {
            "session_id": session_id,
            "anomaly_detected": True,
            "risk_score": 100,
            "severity": "Critical",
            "decision": "BLOCK",
            "indicators": [
                "Unknown or invalid session ID"
            ],
            "explanation": (
                "The supplied session identifier does not belong "
                "to an active CyberGuard session."
            )
        }

    validation = validate_session(session_id)

    if not validation["valid"]:
        return {
            "session_id": session_id,
            "anomaly_detected": True,
            "risk_score": 100,
            "severity": "Critical",
            "decision": "BLOCK",
            "indicators": [
                validation["reason"]
            ],
            "explanation": (
                "The session is no longer valid and must not "
                "be used."
            )
        }

    risk_score = 0
    indicators = []

    # --------------------------------------------------------
    # IP CHANGE
    # --------------------------------------------------------

    original_ip = session.get("ip_address", "")

    if ip_address and original_ip and ip_address != original_ip:

        risk_score += 30

        indicators.append(
            f"Source IP changed from {original_ip} to {ip_address}"
        )

    # --------------------------------------------------------
    # DEVICE CHANGE
    # --------------------------------------------------------

    original_device = session.get("device_id", "")

    if (
        device_id
        and original_device
        and device_id != original_device
    ):

        risk_score += 30

        indicators.append(
            "Device identifier changed during the session"
        )

    # --------------------------------------------------------
    # USER-AGENT CHANGE
    # --------------------------------------------------------

    original_user_agent = session.get("user_agent", "")

    if (
        user_agent
        and original_user_agent
        and user_agent != original_user_agent
    ):

        risk_score += 15

        indicators.append(
            "User-Agent changed during the session"
        )

    # --------------------------------------------------------
    # LOCATION CHANGE
    # --------------------------------------------------------

    original_location = session.get("location", "")

    if (
        location
        and original_location
        and location.lower() != original_location.lower()
    ):

        risk_score += 25

        indicators.append(
            f"Location changed from {original_location} to {location}"
        )

    # --------------------------------------------------------
    # CAP RISK
    # --------------------------------------------------------

    risk_score = min(risk_score, 100)

    severity = _get_severity(risk_score)
    decision = _get_decision(risk_score)

    anomaly_detected = risk_score > 0

    # --------------------------------------------------------
    # UPDATE SESSION MONITORING DATA
    # --------------------------------------------------------

    session["last_risk_score"] = risk_score
    session["last_decision"] = decision

    if anomaly_detected:
        session["anomaly_count"] += 1

    # --------------------------------------------------------
    # EXPLANATION
    # --------------------------------------------------------

    if not anomaly_detected:

        explanation = (
            "No significant session property changes were "
            "detected. The session appears consistent with "
            "its original authentication context."
        )

    elif risk_score >= RISK_BLOCK:

        explanation = (
            "Multiple session properties changed during an "
            "active authenticated session. This behavior is "
            "highly suspicious and may indicate session "
            "hijacking or account takeover."
        )

    elif risk_score >= RISK_MFA:

        explanation = (
            "Significant changes were detected in the active "
            "session context. Additional authentication such "
            "as MFA is recommended before continuing."
        )

    else:

        explanation = (
            "A change was detected in the active session "
            "context. The event should be monitored for "
            "additional suspicious activity."
        )

    return {
        "session_id": session_id,
        "username": session["username"],
        "anomaly_detected": anomaly_detected,
        "risk_score": risk_score,
        "severity": severity,
        "decision": decision,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "anomaly_count": session["anomaly_count"],
        "explanation": explanation
    }


# ============================================================
# SESSION REVOCATION
# ============================================================

def revoke_session(
    session_id: str,
    reason: str = "Session revoked"
):
    """
    Revoke an active session.

    The session is retained in memory for audit/demo purposes,
    but its status is changed to revoked.
    """

    session = ACTIVE_SESSIONS.get(session_id)

    if not session:
        return {
            "revoked": False,
            "reason": "Invalid or unknown session"
        }

    session["status"] = "revoked"
    session["revoked_at"] = _utc_now().isoformat()
    session["revocation_reason"] = reason

    return {
        "revoked": True,
        "session_id": session_id,
        "username": session["username"],
        "status": "revoked",
        "reason": reason,
        "revoked_at": session["revoked_at"]
    }


# ============================================================
# REVOKE ALL USER SESSIONS
# ============================================================

def revoke_user_sessions(
    username: str,
    reason: str = "All user sessions revoked"
):
    """
    Revoke every active session belonging to a user.

    Useful after confirmed account takeover.
    """

    revoked_sessions = []

    for session_id, session in ACTIVE_SESSIONS.items():

        if (
            session["username"] == username
            and session["status"] == "active"
        ):

            result = revoke_session(
                session_id,
                reason
            )

            if result["revoked"]:
                revoked_sessions.append(session_id)

    return {
        "username": username,
        "revoked_count": len(revoked_sessions),
        "revoked_sessions": revoked_sessions,
        "reason": reason
    }


# ============================================================
# ACTIVE SESSIONS
# ============================================================

def get_active_sessions(username: str = None):
    """
    Return active sessions.

    If username is provided, return only that user's sessions.
    """

    cleanup_expired_sessions()

    sessions = []

    for session in ACTIVE_SESSIONS.values():

        if session["status"] != "active":
            continue

        if username and session["username"] != username:
            continue

        sessions.append(session.copy())

    return sessions


# ============================================================
# SESSION CLEANUP
# ============================================================

def cleanup_expired_sessions():
    """
    Mark expired sessions as expired.

    This prevents stale active sessions from remaining in the
    session store indefinitely.
    """

    now = _utc_now()

    expired_count = 0

    for session in ACTIVE_SESSIONS.values():

        if session["status"] != "active":
            continue

        expires_at = _parse_datetime(
            session["expires_at"]
        )

        absolute_expires_at = _parse_datetime(
            session["absolute_expires_at"]
        )

        if (
            now >= expires_at
            or now >= absolute_expires_at
        ):

            session["status"] = "expired"
            session["expired_at"] = now.isoformat()

            expired_count += 1

    return {
        "expired_count": expired_count
    }


# ============================================================
# SESSION STATISTICS
# ============================================================

def get_session_statistics():
    """
    Return basic session statistics for the CyberGuard dashboard.
    """

    cleanup_expired_sessions()

    total = len(ACTIVE_SESSIONS)

    active = 0
    revoked = 0
    expired = 0
    suspicious = 0

    for session in ACTIVE_SESSIONS.values():

        status = session["status"]

        if status == "active":
            active += 1

        elif status == "revoked":
            revoked += 1

        elif status == "expired":
            expired += 1

        if session.get("last_risk_score", 0) > 0:
            suspicious += 1

    return {
        "total_sessions": total,
        "active_sessions": active,
        "revoked_sessions": revoked,
        "expired_sessions": expired,
        "suspicious_sessions": suspicious
    }


# ============================================================
# MODULE TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CYBERGUARD SESSION MANAGER TEST")
    print("=" * 60)

    # --------------------------------------------------------
    # 1. CREATE SESSION
    # --------------------------------------------------------

    session = create_session(
        username="alice",
        ip_address="192.168.1.10",
        device_id="LAPTOP-ALICE",
        user_agent="Chrome-Windows",
        location="Bhubaneswar"
    )

    print("\n[1] SESSION CREATED")
    print(session)

    session_id = session["session_id"]

    # --------------------------------------------------------
    # 2. VALIDATE SESSION
    # --------------------------------------------------------

    validation = validate_session(session_id)

    print("\n[2] SESSION VALIDATION")
    print(validation)

    # --------------------------------------------------------
    # 3. NORMAL SESSION CHECK
    # --------------------------------------------------------

    normal_check = detect_session_anomaly(
        session_id=session_id,
        ip_address="192.168.1.10",
        device_id="LAPTOP-ALICE",
        user_agent="Chrome-Windows",
        location="Bhubaneswar"
    )

    print("\n[3] NORMAL SESSION CHECK")
    print(normal_check)

    # --------------------------------------------------------
    # 4. SUSPICIOUS SESSION CHECK
    # --------------------------------------------------------

    suspicious_check = detect_session_anomaly(
        session_id=session_id,
        ip_address="203.0.113.50",
        device_id="ATTACKER-DEVICE",
        user_agent="Unknown-Browser",
        location="Mumbai"
    )

    print("\n[4] SUSPICIOUS SESSION CHECK")
    print(suspicious_check)

    # --------------------------------------------------------
    # 5. UPDATE ACTIVITY
    # --------------------------------------------------------

    activity = update_session_activity(
        session_id
    )

    print("\n[5] SESSION ACTIVITY UPDATE")
    print(activity)

    # --------------------------------------------------------
    # 6. ACTIVE SESSIONS
    # --------------------------------------------------------

    active = get_active_sessions()

    print("\n[6] ACTIVE SESSIONS")
    print(active)

    # --------------------------------------------------------
    # 7. STATISTICS
    # --------------------------------------------------------

    statistics = get_session_statistics()

    print("\n[7] SESSION STATISTICS")
    print(statistics)

    # --------------------------------------------------------
    # 8. REVOKE SESSION
    # --------------------------------------------------------

    revoked = revoke_session(
        session_id,
        "Possible session takeover detected"
    )

    print("\n[8] SESSION REVOCATION")
    print(revoked)

    # --------------------------------------------------------
    # 9. VALIDATE AFTER REVOCATION
    # --------------------------------------------------------

    validation_after_revoke = validate_session(
        session_id
    )

    print("\n[9] VALIDATION AFTER REVOCATION")
    print(validation_after_revoke)

    print("\n" + "=" * 60)
    print("SESSION MANAGER TEST COMPLETE")
    print("=" * 60)