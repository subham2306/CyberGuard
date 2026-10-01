from app.database import get_connection

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT
        username,
        home_location,
        usual_login_start,
        usual_login_end
    FROM users
    WHERE username = ?
""", ("alice",))

user = cursor.fetchone()

if user:
    print(dict(user))
else:
    print("Alice was not found in the database.")

connection.close()