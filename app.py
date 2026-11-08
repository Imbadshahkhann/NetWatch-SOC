from flask import Flask, render_template, request, redirect, url_for
from database import get_all_alerts, update_alert_status
from collections import Counter
import json
import os

app = Flask(__name__)

STATS_FILE = "traffic_stats.json"


def get_traffic_stats():
    default = {
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "arp_packets": 0,
        "other_packets": 0,
    }

    if not os.path.exists(STATS_FILE):
        return default

    try:
        with open(STATS_FILE, "r", encoding="utf-8") as file:
            return {**default, **json.load(file)}
    except (OSError, json.JSONDecodeError):
        return default


@app.route("/")
def dashboard():
    all_alerts = get_all_alerts()

    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "ALL")
    alert_type = request.args.get("alert_type", "ALL")

    alerts = all_alerts

    if severity != "ALL":
        alerts = [a for a in alerts if a[4] == severity]

    if alert_type != "ALL":
        alerts = [a for a in alerts if a[2] == alert_type]

    if search:
        alerts = [
            a for a in alerts if search.lower() in " ".join(str(x) for x in a).lower()
        ]

    severity_counts = Counter(a[4] for a in all_alerts)
    source_counts = Counter(a[3] for a in all_alerts)
    top_sources = source_counts.most_common(5)

    stats = get_traffic_stats()

    return render_template(
        "index.html",
        alerts=alerts,
        stats=stats,
        total_alerts=len(all_alerts),
        critical_alerts=severity_counts["CRITICAL"],
        high_alerts=severity_counts["HIGH"],
        medium_alerts=severity_counts["MEDIUM"],
        new_alerts=sum(1 for a in all_alerts if a[7] == "NEW"),
        severity_labels=["Critical", "High", "Medium"],
        severity_values=[
            severity_counts["CRITICAL"],
            severity_counts["HIGH"],
            severity_counts["MEDIUM"],
        ],
        source_labels=[item[0] for item in top_sources],
        source_values=[item[1] for item in top_sources],
        search=search,
        selected_severity=severity,
        selected_type=alert_type,
    )


@app.route("/alert/<alert_id>/status", methods=["POST"])
def change_alert_status(alert_id):
    status = request.form.get("status", "")

    if status in ("ACKNOWLEDGED", "RESOLVED"):
        update_alert_status(alert_id, status)

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    print("NetWatch SOC Dashboard Starting...")
    app.run(host="127.0.0.1", port=5000, debug=False)
