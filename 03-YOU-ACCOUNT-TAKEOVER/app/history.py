from datetime import datetime, timedelta, timezone

from app.database import get_connection


def get_recent_failed_attempts(
    username: str,
    minutes: int = 10
) -> int:
    """
    Count failed login attempts for a user
    during the last N minutes.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp
        FROM login_events
        WHERE username = ?
        AND status = 'failed'
        ORDER BY timestamp DESC
    """, (username,))

    rows = cursor.fetchall()

    connection.close()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=minutes)

    count = 0

    for row in rows:

        try:
            event_time = datetime.fromisoformat(
                row["timestamp"]
            )

            if event_time.tzinfo is None:
                event_time = event_time.replace(
                    tzinfo=timezone.utc
                )

            if event_time >= cutoff:
                count += 1

        except (ValueError, TypeError):
            continue

    return count


def get_known_devices(username: str):
    """
    Return devices previously used successfully
    by this user.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT DISTINCT device_id
        FROM login_events
        WHERE username = ?
        AND status = 'success'
        AND device_id IS NOT NULL
    """, (username,))

    rows = cursor.fetchall()

    connection.close()

    return {
        row["device_id"]
        for row in rows
    }


def get_known_ips(username: str):
    """
    Return IP addresses previously used successfully
    by this user.
    """

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT DISTINCT ip_address
        FROM login_events
        WHERE username = ?
        AND status = 'success'
        AND ip_address IS NOT NULL
    """, (username,))

    rows = cursor.fetchall()

    connection.close()

    return {
        row["ip_address"]
        for row in rows
    }