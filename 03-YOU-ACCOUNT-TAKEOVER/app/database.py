import sqlite3
from pathlib import Path


# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent

# SQLite database location
DB_PATH = BASE_DIR / "cyberguard.db"


def get_connection():
    """
    Create and return a connection to the SQLite database.
    """

    connection = sqlite3.connect(DB_PATH)

    # Allows us to access columns by name
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create all required database tables.
    """

    connection = get_connection()
    cursor = connection.cursor()

    # ------------------------------------------------
    # USERS TABLE
    # ------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            home_location TEXT,
            usual_device TEXT,
            usual_login_start INTEGER DEFAULT 8,
            usual_login_end INTEGER DEFAULT 22,
            mfa_enabled INTEGER DEFAULT 1,
            account_locked INTEGER DEFAULT 0,
            password_reset_required INTEGER DEFAULT 0
        )
    """)

    # ------------------------------------------------
    # LOGIN EVENTS TABLE
    # ------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_events (
            event_id TEXT PRIMARY KEY,
            user_id TEXT,
            username TEXT,
            timestamp TEXT,
            ip_address TEXT,
            location TEXT,
            device_id TEXT,
            status TEXT,
            risk_score REAL,
            severity TEXT,
            decision TEXT,
            indicators TEXT
        )
    """)

    # ------------------------------------------------
    # IP BLOCKLIST TABLE
    # ------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocks (
            ip_address TEXT PRIMARY KEY,
            blocked_until TEXT,
            reason TEXT
        )
    """)

    # ------------------------------------------------
    # SESSIONS TABLE
    # ------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT,
            ip_address TEXT,
            device_id TEXT,
            created_at TEXT,
            active INTEGER DEFAULT 1
        )
    """)

    connection.commit()
    connection.close()


if __name__ == "__main__":

    initialize_database()

    print("CyberGuard database initialized successfully.")
    print(f"Database location: {DB_PATH}")