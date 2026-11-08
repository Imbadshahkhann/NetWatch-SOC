import sqlite3

DB_NAME = "netwatch.db"

VALID_STATUSES = ("NEW", "ACKNOWLEDGED", "RESOLVED")


def get_connection():
    return sqlite3.connect(DB_NAME)


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT,
                alert_type TEXT,
                source_ip TEXT,
                severity TEXT,
                description TEXT,
                mitre_technique TEXT,
                status TEXT
            )
        """)

    print("[DATABASE] Database initialized successfully")


def save_alert(alert):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO alerts (
                alert_id, timestamp, alert_type, source_ip,
                severity, description, mitre_technique, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                alert["alert_id"],
                alert["timestamp"],
                alert["alert_type"],
                alert["source_ip"],
                alert["severity"],
                alert["description"],
                alert["mitre_technique"],
                alert["status"],
            ),
        )

    print("[DATABASE] Alert saved successfully")


def get_all_alerts():
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        return cursor.fetchall()


def update_alert_status(alert_id, status):
    if status not in VALID_STATUSES:
        print("[DATABASE] Invalid alert status")
        return False

    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE alerts
            SET status = ?
            WHERE alert_id = ?
        """,
            (status, alert_id),
        )

        if cursor.rowcount == 0:
            print("[DATABASE] Alert not found")
            return False

    print(f"[DATABASE] Alert status updated to {status}")
    return True


if __name__ == "__main__":
    initialize_database()
