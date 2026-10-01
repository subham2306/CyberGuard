import hashlib
import hmac


def hash_password(password: str) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    """

    salt = b"cyberguard-demo-salt"

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000
    )

    return password_hash.hex()


def verify_password(password: str, stored_password: str) -> bool:
    """
    Verify a password against the stored hash.
    """

    return hmac.compare_digest(
        hash_password(password),
        stored_password
    )