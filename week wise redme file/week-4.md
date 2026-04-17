# 🚀 Advanced Threat Intelligence Platform (TIP)

---

## 📌 Week 4: Monitoring, Safety Controls & Final Reporting

### 📖 Description
Week 4 focuses on enhancing the reliability, safety, and completeness of the Threat Intelligence Platform (TIP). This phase introduces monitoring mechanisms, rollback functionality for false positives, and final system documentation.

The system now supports real-time threat blocking, monitoring, and recovery, making it production-ready.

### 🎯 Objectives
- Implement rollback mechanism for false positives
- Add monitoring and logging system
- Enhance Kibana dashboards
- Perform end-to-end system testing
- Document full architecture
- Prepare final project and GitHub repository

---

## 🛠️ Technologies Used
- **Python** – Firewall automation & monitoring
- **MongoDB** – Threat storage and status tracking
- **Elasticsearch** – Indexing and fast querying
- **Kibana** – Visualization dashboards
- **iptables / hosts / squid / postfix** – Blocking mechanisms
- **Logging** (`logging` module) – Monitoring & audit

---

## ⚙️ Key Features Implemented

### 🔥 1. Dynamic Firewall Engine
- Automatically blocks high-risk threats (`risk_score ≥ 80`)
- Supports multiple IOC types:
  - IP, Domain, URL
  - Hash (MD5, SHA1, SHA256)
  - Email, CIDR
  - JA3, Certificate

### 🔄 2. Rollback Mechanism (Safety Control)
- Automatically removes blocks after a defined time (e.g., 24 hours)
- Prevents false positives from permanently blocking resources
- Updates MongoDB with rollback status

### 📡 3. Monitoring & Logging
- Real-time logging of:
  - Blocked threats
  - Errors
  - System activity
- **Log files outputted:**
  - `dynamic_firewall.log`
  - `threat_hashes.log`

### 📊 4. Advanced Kibana Dashboard
**Includes:**
- Total Threats
- High Risk Threats
- Blocked vs Active
- Threat Type Distribution
- Severity Distribution
- Risk Score Histogram
- Top Threat Sources
- Blocked Threat Types 🔥
- Threat Timeline 📈
- Blocked Threat Logs (Live) 📋
- System Status Panel

### 🧪 5. End-to-End Testing
**Verified full pipeline:**
`Data Collection` → `MongoDB` → `Elasticsearch` → `Kibana` → `Firewall Blocking`

**Confirmed:**
- Data indexing
- Visualization
- Real-time blocking
- Database updates

---

## 🔄 Data Flow
```text
OSINT Sources
      ↓
MongoDB (Threat Storage)
      ↓
Elasticsearch (Indexing)
      ↓
Kibana Dashboard (Visualization)
      ↓
Firewall Engine (Blocking & Monitoring)
```

---

## ⚠️ Challenges Faced
- False positives in blocking.
- Managing multiple threat types.
- Sync issues between MongoDB and firewall.
- Missing timestamps for timeline visualization.

## ✅ Solutions
- Implemented rollback system for safety.
- Created modular threat handler (`block_threat`).
- Added logging for debugging and monitoring.

---

## 🚀 Final Outcome
Successfully built a complete Threat Intelligence Platform with:

- ✔ Automated threat collection
- ✔ Real-time visualization dashboards
- ✔ Dynamic firewall enforcement
- ✔ Multi-type threat blocking
- ✔ Monitoring and logging system
- ✔ Rollback safety mechanism

### 📌 Conclusion
The system is now fully operational and capable of detecting, analyzing, and mitigating cyber threats in real time. It provides strong visibility, automation, and safety controls, making it suitable for practical cybersecurity applications.