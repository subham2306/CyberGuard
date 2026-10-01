from app.database import get_connection, initialize_database
from app.auth import hash_password


USERS = [
    {
        "user_id": "USR001",
        "username": "alice",
        "password": hash_password("Alice@123"),
        "home_location": "Bhubaneswar",
        "usual_device": "DEV001",
        "usual_login_start": 8,
        "usual_login_end": 22
    },
    {
        "user_id": "USR002",
        "username": "bob",
        "password": hash_password("Bob@123"),
        "home_location": "Cuttack",
        "usual_device": "DEV002",
        "usual_login_start": 8,
        "usual_login_end": 22
    },
    {
        "user_id": "USR003",
        "username": "charlie",
        "password": hash_password("Charlie@123"),
        "home_location": "Bhubaneswar",
        "usual_device": "DEV003",
        "usual_login_start": 9,
        "usual_login_end": 21
    }
]


def seed_users():

    initialize_database()

    connection = get_connection()
    cursor = connection.cursor()

    for user in USERS:

        try:

            cursor.execute("""
                INSERT INTO users (
                    user_id,
                    username,
                    password,
                    home_location,
                    usual_device,
                    usual_login_start,
                    usual_login_end
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user["user_id"],
                user["username"],
                user["password"],
                user["home_location"],
                user["usual_device"],
                user["usual_login_start"],
                user["usual_login_end"]
            ))

            print(f"Created user: {user['username']}")

        except sqlite3.IntegrityError:

            print(f"User already exists: {user['username']}")

    connection.commit()
    connection.close()

    print("\nCyberGuard demo users are ready.")


if __name__ == "__main__":
    seed_users()