# 🚀 Advanced Threat Intelligence Platform (TIP)

## 📌 Overview
The Threat Intelligence Platform (TIP) is a complete cybersecurity solution that collects, processes, analyzes, visualizes, and actively blocks malicious threats in real-time.

This project integrates:
* **Data Collection (OSINT)**
* **Data Storage (MongoDB)**
* **Search & Analytics (Elasticsearch)**
* **Visualization (Kibana)**
* **Automated Firewall Enforcement**

## 🎯 Objectives
* Collect threat intelligence from multiple OSINT sources
* Store and normalize data in MongoDB
* Index and search data using Elasticsearch
* Visualize threat patterns using Kibana dashboards
* Automatically block high-risk threats using firewall rules
* Implement rollback and monitoring for safety

## 🛠️ Technologies Used
| Technology | Purpose |
| :--- | :--- |
| **Python** | Core scripting & automation |
| **MongoDB** | Threat data storage |
| **Elasticsearch** | Fast indexing & search |
| **Kibana** | Visualization dashboards |
| **IPTables** | Firewall blocking |
| **OSINT APIs** | Threat intelligence collection |

## 📂 Project Structure
```text
threat-intelligence-platform/
│
├── src/
│   ├── collectors/
│   ├── database/
│   ├── processors/
│   └── services/
│
├── assets/              # Dashboard & output screenshots
├── Project Directory Structure/              # Project folder Directory
├── Week aise redme file/                # Week-wise documentation
│   ├── week-1.md
│   ├── week-2.md
│   ├── week-3.md
│   └── week-4.md
│
├── firewall_engine.py   # Dynamic firewall system
├── firewall.py          # Blocking logic
├── mongo_to_elastic.py  # Data pipeline
├── monitor.py           # Monitoring system
├── rollback.py          # Safety rollback
├── run_collectors.py    # Data collection runner
├── config.py
├── utils.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

## 🔄 System Architecture
```text
OSINT Sources
     ↓
Collectors (Python)
     ↓
MongoDB (Storage)
     ↓
Processors (Normalization + Deduplication)
     ↓
Elasticsearch (Indexing)
     ↓
Kibana Dashboard (Visualization)
     ↓
Firewall Engine (Auto Blocking)
```

## 🔥 Firewall Capabilities
| Threat Type | Action |
| :--- | :--- |
| **IP** | Block using IPTables |
| **Domain** | Block via `/etc/hosts` |
| **URL** | Block via Squid |
| **Hash** | Logged + YARA rules |
| **Email** | Postfix blacklist |
| **CIDR** | Network blocking |
| **JA3** | TLS fingerprint blocking |
| **Certificate** | SSL block |

## 📊 Kibana Dashboard Features
* 📊 **Total Threats**
* 🚨 **High Risk Threats**
* 🔥 **Blocked vs Active**
* 🌐 **Threat Types**
* ⚠️ **Severity Distribution**
* 📈 **Risk Score Histogram**
* 📡 **Top Sources**
* 🛡️ **Blocked Threat Types**
* ⏳ **Timeline Graph**
* 📋 **Live Blocked Threat Logs**
* 🔐 **System Status Panel**

## 🧪 How to Run the Project

**1️⃣ Install Dependencies**
```bash
pip install -r requirements.txt
```

**2️⃣ Start Services**
```bash
sudo systemctl start mongodb
sudo systemctl start elasticsearch
sudo systemctl start kibana
```

**3️⃣ Run Data Collection**
```bash
python3 run_collectors.py
```

**4️⃣ Push Data to Elasticsearch**
```bash
python3 mongo_to_elastic.py
```

**5️⃣ Start Firewall Engine**
```bash
python3 firewall_engine.py
```

**6️⃣ Open Dashboard**
Navigate to `http://localhost:5601` in your web browser.

## 🔐 Safety Features
* Rollback system for false positives
* Logging of all blocked threats
* Controlled risk threshold (≥ 80)
* Duplicate prevention
* Real-time monitoring

## ⚠️ Challenges Faced & ✅ Solutions
* **Elasticsearch TLS issues** ➔ Cleaned and normalized data
* **Data normalization problems** ➔ Used bulk indexing API
* **Duplicate threat entries** ➔ Implemented modular architecture
* **Firewall rule management** ➔ Added type-based routing system
* **Multi-type threat handling** ➔ Integrated logging & rollback

## 🎯 Final Outcome
* ✔ Fully functional Threat Intelligence Platform
* ✔ Real-time threat detection and blocking
* ✔ Interactive dashboards for analysis
* ✔ Automated cybersecurity defense system

## 📸 Screenshots
👉 See `assets/` folder for Dashboard views, Firewall logs, and Data pipeline results.

---
👨‍💻 **Authors:** Prathana Lovish Sunny Reniz

### 🏁 Conclusion
This project demonstrates a complete end-to-end cybersecurity pipeline, combining data engineering, threat intelligence, and active defense mechanisms into one scalable system.
