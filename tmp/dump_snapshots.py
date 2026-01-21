import sqlite3
import os

db_path = '.zscope_snapshots/snapshots.db'
if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute('SELECT func_name, code_hash, semantic_hash, location, timestamp FROM snapshots')
    rows = cursor.fetchall()

    print(f"| {'Function Name':<25} | {'Location':<40} | {'Semantic Hash':<15} | {'Timestamp':<20} |")
    print("|" + "-"*27 + "|" + "-"*42 + "|" + "-"*17 + "|" + "-"*22 + "|")
    
    for r in rows:
        name = r[0]
        loc = r[3]
        s_hash = r[2][:12] if r[2] else "N/A"
        ts = r[4]
        print(f"| {name:<25} | {loc:<40} | {s_hash:<15} | {ts:<20} |")
        
except sqlite3.Error as e:
    print(f"SQLite error: {e}")
finally:
    conn.close()
