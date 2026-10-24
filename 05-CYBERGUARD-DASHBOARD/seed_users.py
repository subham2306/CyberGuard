from getpass import getpass

from backend.database import init_database
from backend.auth import create_user, user_exists


def create_account(username: str, role: str):
    if user_exists(username):
        print(f"{role} account '{username}' already exists.")
        return

    password = getpass(f"Enter password for {role} '{username}': ")

    if not password:
        print("Password cannot be empty.")
        return

    confirmation = getpass("Confirm password: ")

    if password != confirmation:
        print("Passwords do not match.")
        return

    if create_user(username, password, role):
        print(f"{role} account '{username}' created successfully.")
    else:
        print(f"Could not create {role} account.")


if __name__ == "__main__":
    init_database()

    print("=== CyberGuard Dashboard User Setup ===")
    print()

    create_account("admin", "ADMIN")
    create_account("user", "USER")
