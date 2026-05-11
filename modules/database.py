import sqlite3

DB_NAME = "threat_intel.db"


# ---------------- CREATE DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT,
        type TEXT,
        source TEXT,
        timestamp TEXT,
        severity TEXT
    )
    """)

    conn.commit()
    conn.close()


# ---------------- SAVE IOCS ----------------
def save_iocs(ioc_list):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    for item in ioc_list:
        cursor.execute("""
        INSERT INTO iocs (value, type, source, timestamp, severity)
        VALUES (?, ?, ?, ?, ?)
        """, (
            item["ioc"],
            item.get("type", "unknown"),
            item.get("source", "feed"),
            item.get("timestamp", ""),
            item.get("severity", "LOW")
        ))

    conn.commit()
    conn.close()


# ---------------- LOAD IOCS ----------------
def load_iocs():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM iocs ORDER BY id DESC")

    rows = cursor.fetchall()

    conn.close()

    return rows