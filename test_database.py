from database import initialize_database, save_alert, get_all_alerts
from datetime import datetime
import uuid

initialize_database()

test_alert = {
    "alert_id": str(uuid.uuid4()),
    "timestamp": datetime.now().isoformat(),
    "alert_type": "Test Port Scan",
    "source_ip": "192.168.1.50",
    "severity": "HIGH",
    "description": "Database integration test",
    "mitre_technique": "T1046",
    "status": "NEW",
}

save_alert(test_alert)

print("\nReading alerts from database:")

for alert in get_all_alerts():
    print(alert)
