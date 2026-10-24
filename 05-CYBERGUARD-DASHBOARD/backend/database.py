import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "cyberguard_dashboard.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'USER')),
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT,
            module TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            risk_score REAL DEFAULT 0,
            severity TEXT,
            decision TEXT,
            confidence REAL,
            indicators TEXT,
            raw_result TEXT
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_database()
    print(f"CyberGuard dashboard database initialized: {DB_PATH}")
