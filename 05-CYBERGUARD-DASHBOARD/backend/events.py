import json
from datetime import datetime
from zoneinfo import ZoneInfo

from .database import get_connection


IST = ZoneInfo("Asia/Kolkata")


def log_security_event(
    username=None,
    module="Unknown",
    event_type="Unknown",
    source_ip=None,
    risk_score=0,
    severity=None,
    decision=None,
    confidence=None,
    indicators=None,
    raw_result=None,
):
    """
    Store one CyberGuard security detection in the dashboard database.
    """

    timestamp = datetime.now(IST).isoformat(timespec="seconds")

    if indicators is not None and not isinstance(indicators, str):
        indicators = json.dumps(indicators, ensure_ascii=False)

    if raw_result is not None and not isinstance(raw_result, str):
        raw_result = json.dumps(raw_result, ensure_ascii=False)

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO security_events (
                timestamp,
                username,
                module,
                event_type,
                source_ip,
                risk_score,
                severity,
                decision,
                confidence,
                indicators,
                raw_result
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                username,
                module,
                event_type,
                source_ip,
                float(risk_score or 0),
                severity,
                decision,
                confidence,
                indicators,
                raw_result,
            ),
        )

        conn.commit()

        return cursor.lastrowid

    finally:
        conn.close()


def get_recent_events(limit=20):
    """
    Return the most recent security events.
    """

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                timestamp,
                username,
                module,
                event_type,
                source_ip,
                risk_score,
                severity,
                decision,
                confidence,
                indicators,
                raw_result
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        )

        return [dict(row) for row in cursor.fetchall()]

    finally:
        conn.close()


def get_event_counts():
    """
    Return basic dashboard statistics.
    """

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) AS total FROM security_events"
        )
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE COALESCE(risk_score, 0) >= 50
            """
        )
        threats = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE UPPER(COALESCE(severity, '')) = 'CRITICAL'
            """
        )
        critical = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE UPPER(COALESCE(decision, '')) IN
                  ('BLOCK', 'MFA_REQUIRED')
            """
        )
        incidents = cursor.fetchone()["total"]

        return {
            "total_events": total,
            "threats_detected": threats,
            "critical_threats": critical,
            "active_incidents": incidents,
        }

    finally:
        conn.close()
