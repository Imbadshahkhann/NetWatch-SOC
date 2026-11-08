from alert_manager import create_alert

create_alert(
    alert_type="Port Scan",
    source_ip="192.168.1.50",
    severity="HIGH",
    description="20 unique ports accessed within 10 seconds",
    mitre_id="T1046",
)

print("\nAlert Manager Test Completed")
