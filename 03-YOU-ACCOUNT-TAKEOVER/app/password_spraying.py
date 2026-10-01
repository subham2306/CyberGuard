from app.database import get_connection


def detect_password_spraying(
    ip_address: str,
    minutes: int = 10,
    username_threshold: int = 3,
    attempt_threshold: int = 5
):
    """
    Detect possible password spraying from a single source IP.

    This is intended for the controlled CyberGuard demo
    environment.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            COUNT(*) AS failed_attempts,
            COUNT(DISTINCT username) AS targeted_users
        FROM login_events
        WHERE ip_address = ?
          AND status = 'failed'
          AND datetime(timestamp) >= datetime('now', ?)
        """,
        (
            ip_address,
            f"-{minutes} minutes"
        )
    )

    result = cursor.fetchone()

    connection.close()

    failed_attempts = int(result["failed_attempts"] or 0)
    targeted_users = int(result["targeted_users"] or 0)

    spraying_detected = (
        targeted_users >= username_threshold
        and failed_attempts >= attempt_threshold
    )

    return {
        "ip_address": ip_address,
        "failed_attempts": failed_attempts,
        "targeted_users": targeted_users,
        "spraying_detected": spraying_detected
    }