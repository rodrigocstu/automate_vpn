import sqlite3
import os

db_path = os.path.join("instance", "vpnapp_qa.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

try:
    print("--- SCHEMA users ---")
    schema = cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    print(schema['sql'] if schema else "Table users not found")
    
    print("\n--- DATA users (First 5) ---")
    rows = cursor.execute("SELECT * FROM users LIMIT 5").fetchall()
    for row in rows:
        print(dict(row))
        
except Exception as e:
    print(f"Error: {e}")
finally:
    conn.close()
