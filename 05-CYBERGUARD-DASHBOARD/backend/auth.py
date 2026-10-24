import hashlib
import secrets
from datetime import datetime, timezone

from .database import get_connection


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200_000,
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected_hash = stored_hash.split("$", 1)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            200_000,
        ).hex()

        return secrets.compare_digest(password_hash, expected_hash)

    except ValueError:
        return False


def create_user(username: str, password: str, role: str) -> bool:
    role = role.upper()

    if role not in {"ADMIN", "USER"}:
        raise ValueError("Role must be ADMIN or USER")

    conn = get_connection()

    try:
        conn.execute(
            """
            INSERT INTO users
                (username, password_hash, role, created_at)
            VALUES
                (?, ?, ?, ?)
            """,
            (
                username,
                hash_password(password),
                role,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        conn.commit()
        return True

    except Exception:
        return False

    finally:
        conn.close()


def authenticate_user(username: str, password: str):
    conn = get_connection()

    try:
        row = conn.execute(
            """
            SELECT id, username, password_hash, role
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if row is None:
            return None

        if not verify_password(password, row["password_hash"]):
            return None

        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }

    finally:
        conn.close()


def user_exists(username: str) -> bool:
    conn = get_connection()

    try:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        return row is not None

    finally:
        conn.close()


if __name__ == "__main__":
    print("CyberGuard authentication module loaded successfully.")
