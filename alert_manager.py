import json
import uuid
from datetime import datetime
from database import initialize_database, save_alert

ALERT_FILE = "alerts.jsonl"

# Prepare the database
initialize_database()


def create_alert(alert_type, source_ip, severity, description, mitre_id=None):

    alert = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "source_ip": source_ip,
        "severity": severity,
        "description": description,
        "mitre_technique": mitre_id,
        "status": "NEW",
    }

    # Save alert to SQLite database
    save_alert(alert)

    # Save alert to JSONL file
    with open(ALERT_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(alert) + "\n")

    # Display alert in terminal
    print("\n[NETWATCH SECURITY ALERT]")
    print(json.dumps(alert, indent=4))

    return alert
