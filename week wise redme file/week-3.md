# 🚀 Advanced Threat Intelligence Platform (TIP)

---

## 📌 Week 3: Automated Threat Detection & Firewall Engine

### 📖 Description
This phase enhances the Threat Intelligence Platform by introducing an automated firewall engine that actively detects and blocks high-risk threats in real time. The system continuously monitors threat data stored in MongoDB and applies appropriate mitigation techniques based on threat type, enabling proactive cybersecurity defense.

### 🎯 Objectives
- Monitor threat intelligence data in real-time
- Identify high-risk threats using risk scoring
- Automatically block malicious indicators
- Support multiple IOC (Indicators of Compromise) types
- Maintain logs and update threat status dynamically

---

## 🛠️ Technologies Used
- **Python** – Automation & scripting
- **MongoDB** – Threat data storage
- **iptables** – Network-level IP blocking
- **/etc/hosts** – Domain blocking
- **Squid Proxy** – URL filtering
- **Postfix** – Email blocking
- **Suricata** – JA3 & certificate blocking
- **YARA** – Hash-based malware detection

---

## ⚙️ Setup Instructions

### 1️⃣ Run Firewall Engine
```bash
python3 firewall_engine.py
```

### 2️⃣ Ensure Required Permissions
```bash
sudo su
```

### 3️⃣ Required Services (Optional but Recommended)
```bash
sudo systemctl start squid
sudo systemctl start postfix
sudo systemctl start suricata
```

---

## 🔄 Data Flow
```text
MongoDB  →  Firewall Engine  →  System-Level Blocking (iptables, hosts, proxy, etc.)
```

## 🔐 Threat Handling Mechanism

| Threat Type | Action Taken |
|------------|-------------|
| **IP** | Blocked using `iptables` |
| **CIDR** | Blocked using `iptables` |
| **Domain** | Blocked via `/etc/hosts` |
| **URL** | Blocked using `Squid proxy` |
| **Hash** | Logged + `YARA` rule created |
| **Email** | Blocked via `Postfix` |
| **Filename** | Logged for monitoring |
| **JA3** | Blocked via `Suricata` |
| **Certificate** | Blocked via `Suricata` |

---

## ⚡ Key Features
- 🔄 **Real-Time Monitoring** (continuous loop)
- 🎯 **Risk-Based Filtering** (threshold ≥ 80)
- 🔥 **Automated Blocking Engine**
- 📊 **Threat Type Breakdown Logging**
- 🧠 **Smart Routing System** (`block_threat`)
- ✅ **Duplicate Prevention** using in-memory tracking
- 🗃️ **MongoDB Status Sync** (`blocked = True`)

---

## 📊 Sample Output
```text
🔥 Firewall Engine Started (Threshold >= 80)
🚨 Found 500 high-risk indicator(s) [ip:300 | domain:120 | hash:80]
🔥 [IPTABLES] Blocked IP: 192.168.x.x
🔥 [HOSTS] Blocked Domain: malicious.com
🔥 [HASH-SHA256] Malicious Hash Quarantined
```

---

## ⚠️ Challenges Faced
- Handling multiple threat types dynamically.
- Preventing duplicate firewall rules.
- Validating different IOC formats (IP, domain, hash, etc.).
- Integrating multiple system tools (`iptables`, `squid`, `postfix`).
- Managing permissions for system-level operations.

## ✅ Solutions
- Implemented a central routing function (`block_threat`).
- Used regex validation for accurate IOC filtering.
- Added duplicate tracking using sets.
- Used `try-except` handling for stability.
- Created modular blocking functions for each threat type.

## 🚀 Outcome
Successfully developed an advanced automated firewall engine capable of detecting and blocking multiple types of cyber threats in real time.
