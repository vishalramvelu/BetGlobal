import sqlite3

# Connect to your SQLite database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Execute a query to fetch all rows from a table
cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

# Print each row
for row in rows:
    print(row)

# Close the connection
conn.close()



