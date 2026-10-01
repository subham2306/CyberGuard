from datetime import datetime, timezone, timedelta
import secrets


# ============================================================
# CYBERGUARD MFA MODULE
# ============================================================

# In-memory MFA challenge store.
# Suitable for the hackathon prototype.
MFA_CHALLENGES = {}


# ============================================================
# GENERATE MFA CHALLENGE
# ============================================================

def create_mfa_challenge(username: str, validity_minutes: int = 5):
    """
    Create a temporary MFA challenge and a 6-digit OTP.
    """

    challenge_id = (
        f"MFA-{secrets.token_hex(4).upper()}"
    )

    otp = f"{secrets.randbelow(1000000):06d}"

    created_at = datetime.now(timezone.utc)

    expires_at = (
        created_at
        + timedelta(minutes=validity_minutes)
    )

    MFA_CHALLENGES[challenge_id] = {
        "challenge_id": challenge_id,
        "username": username,
        "otp": otp,
        "created_at": created_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "verified": False
    }

    return {
        "challenge_id": challenge_id,
        "username": username,
        "otp": otp,
        "expires_at": expires_at.isoformat()
    }


# ============================================================
# VERIFY MFA
# ============================================================

def verify_mfa_challenge(
    challenge_id: str,
    otp: str
):
    """
    Verify the supplied MFA OTP.
    """

    challenge = MFA_CHALLENGES.get(
        challenge_id
    )

    # --------------------------------------------------------
    # CHALLENGE NOT FOUND
    # --------------------------------------------------------

    if not challenge:

        return {
            "verified": False,
            "reason": "Invalid or unknown MFA challenge"
        }

    # --------------------------------------------------------
    # ALREADY VERIFIED
    # --------------------------------------------------------

    if challenge["verified"]:

        return {
            "verified": False,
            "reason": "MFA challenge has already been used"
        }

    # --------------------------------------------------------
    # CHECK EXPIRATION
    # --------------------------------------------------------

    expires_at = datetime.fromisoformat(
        challenge["expires_at"]
    )

    now = datetime.now(timezone.utc)

    if now >= expires_at:

        del MFA_CHALLENGES[challenge_id]

        return {
            "verified": False,
            "reason": "MFA challenge has expired"
        }

    # --------------------------------------------------------
    # CHECK OTP
    # --------------------------------------------------------

    if str(otp) != str(challenge["otp"]):

        return {
            "verified": False,
            "reason": "Invalid MFA code"
        }

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    challenge["verified"] = True

    return {
        "verified": True,
        "username": challenge["username"],
        "challenge_id": challenge_id,
        "message": "MFA verification successful"
    }


# ============================================================
# GET MFA CHALLENGE
# ============================================================

def get_mfa_challenge(challenge_id: str):

    return MFA_CHALLENGES.get(
        challenge_id
    )