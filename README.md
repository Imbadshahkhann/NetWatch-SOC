# 🛡️ NetWatch SOC

### Network Traffic Monitoring and Anomaly Detection System

NetWatch SOC is a Python-based Security Operations Center (SOC) monitoring project that captures network traffic, detects suspicious activities, generates security alerts, and displays them through a Flask-based dashboard.

## 🚀 Features

- Live network packet capture using Scapy
- Port scan detection
- ARP spoofing detection
- DNS tunnelling detection
- MITRE ATT&CK technique mapping
- SQLite database for security alerts
- Real-time network statistics
- Flask-based SOC dashboard
- Security analytics using Chart.js
- Alert search and severity filtering
- Alert acknowledgement and resolution
- Automated detector testing

## 🧰 Technologies

- Python
- Scapy
- Flask
- SQLite
- HTML5 and CSS3
- JavaScript
- Chart.js
- MITRE ATT&CK

## 📁 Project Structure

```text
NetWatch-SOC/
├── app.py
├── main.py
├── database.py
├── alert_manager.py
├── capture_packets.py
├── network_info.py
├── port_scan_detector.py
├── arp_spoof_detector.py
├── dns_tunnel_detector.py
├── view_alerts.py
├── templates/
│   └── index.html
├── test_alert_manager.py
├── test_all_detectors.py
├── test_arp_spoof.py
├── test_database.py
├── test_dns.py
├── test_port_scan.py
├── requirements.txt
├── .gitignore
└── README.md
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/Imbadshahkhann/NetWatch-SOC.git
```

### 2. Enter the project directory

```bash
cd NetWatch-SOC
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

## ▶️ Run NetWatch SOC

Open two separate PowerShell terminals.

**Terminal 1 — Start network monitoring**

```powershell
python main.py
```

**Terminal 2 — Start the dashboard**

```powershell
python app.py
```

Open your browser:

http://127.0.0.1:5000

Configure the appropriate network interface and install Npcap on Windows before starting packet capture.

## 🔍 Detection Techniques

| Detection      | MITRE ATT&CK |
| -------------- | ------------ |
| Port Scanning  | T1046        |
| ARP Spoofing   | T1557.002    |
| DNS Tunnelling | T1071.004    |

These detection methods use heuristics and may produce false positives. Alerts should be investigated before being treated as confirmed attacks.

## 🧪 Testing

Run individual tests:

```powershell
python test_port_scan.py
python test_arp_spoof.py
python test_dns.py
python test_database.py
python test_alert_manager.py
```

Run all detector tests:

```powershell
python test_all_detectors.py
```

Tests may use simulated traffic and do not represent confirmed real-world attacks.

## 🔐 Responsible Usage

- Monitor only networks you own or have permission to test.
- Do not publish sensitive packet captures or private network information.
- Keep API keys and credentials outside the public repository.
- Investigate and validate generated security alerts.

## 🔮 Future Improvements

- Advanced threat intelligence enrichment
- IOC investigation workflow
- CSV alert reporting
- User authentication
- Improved detection accuracy
- Enhanced incident investigation

## 👨‍💻 Author

**Badshah Khan**

Cybersecurity Student | SOC Analyst | Security Researcher

GitHub: [Imbadshahkhann](https://github.com/Imbadshahkhann)

---

**NetWatch SOC — Monitor. Detect. Investigate.**
