from database import initialize_database, get_all_alerts

initialize_database()

alerts = get_all_alerts()

print(f"\nTotal alerts stored: {len(alerts)}")

for alert in alerts:
    print("\n" + "=" * 50)
    print("Alert ID:", alert[0])
    print("Timestamp:", alert[1])
    print("Alert Type:", alert[2])
    print("Source IP:", alert[3])
    print("Severity:", alert[4])
    print("Description:", alert[5])
    print("MITRE Technique:", alert[6])
    print("Status:", alert[7])
