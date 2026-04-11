
# 🛡 Advanced Threat Intelligence Platform (TIP)

---

# 🔥 Week 3: Dynamic Firewall Enforcement Engine

---

## 🎯 Objective

The objective of Week 3 was to develop an automated security response system that monitors high-risk threat indicators from MongoDB and dynamically enforces firewall rules to block malicious IP addresses using Linux iptables.

---

## 🧰 1. Environment Setup

The firewall engine was developed and tested on a Linux environment (Ubuntu/Kali recommended).

### Tools Required:

* Python 3.x
* MongoDB
* Linux OS
* iptables
* Git

### Python Libraries:

```bash
pip install pymongo
```

---

## 📁 2. Project Structure

```text
threat-intelligence-platform/
│
├── src/
│   ├── firewall/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── firewall.py
│   │   ├── database.py
│   │   └── firewall_engine.py
│
├── logs/
│   └── dynamic_firewall.log
│
├── blocked_ips.txt
├── requirements.txt
└── README.md
```

---

## 🗄 3. MongoDB Monitoring Integration

The firewall engine continuously monitors the MongoDB database for high-risk active indicators.

### Database Details:

* **Database**: `threat_intel`
* **Collection**: `indicators`

### Query Logic:

```python
collection.find({
    "risk_score": {"$gte": 80},
    "status": "active"
})
```

### Features:

* Filters only high-risk indicators
* Processes only active threats
* Runs at configurable time intervals

---

## 🔥 4. Firewall Automation (iptables Integration)

The system automatically generates firewall rules for malicious IP addresses.

### Example Rule:

```bash
iptables -A INPUT -s <malicious_ip> -j DROP
```

### Python Execution:

```python
subprocess.run(
    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
    check=True
)
```

### Features:

* Validates IP address format
* Prevents duplicate firewall rules
* Checks existing rules before adding
* Handles execution errors safely

---

## 💾 5. Persistent Storage

To prevent duplicate blocking:

* Blocked IPs are stored in:

```
blocked_ips.txt
```

### Benefits:

* Prevents repeated rule insertion
* Improves performance
* Maintains blocked history

---

## 📜 6. Logging System

All firewall actions are logged in:

```
logs/dynamic_firewall.log
```

### Logging Includes:

* Successful IP blocks
* Invalid IP attempts
* Database errors
* Firewall execution errors
* Shutdown events

---

## 🔄 7. Daemon Service Implementation

The firewall engine runs continuously as a background service.

### Features:

* Infinite monitoring loop
* Configurable check interval
* Graceful shutdown handling (SIGINT, SIGTERM)
* Automated execution

### Core Loop:

```python
while running:
    monitor_database()
    time.sleep(CHECK_INTERVAL)
```

---

## ▶️ 8. Execution Process (Linux)

### 🟢 1. Navigate to Project

```bash
cd threat-intelligence-platform
```

### 🟢 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 🟢 3. Start MongoDB

```bash
mongod
```

### 🟢 4. Run Firewall Engine

```bash
sudo python src/firewall/firewall_engine.py
```

---

## 🧪 9. Testing the Automation

### Step 1: Insert Test Data

```bash
mongosh
use threat_intel
db.indicators.insertOne({
  indicator_type: "ip",
  value: "192.168.1.100",
  risk_score: 90,
  status: "active"
})
```

### Step 2: Verify Firewall Rule

```bash
sudo iptables -L INPUT -n
```

### Expected Result:

The malicious IP should appear in DROP rules.

---

## ⚠️ 10. Challenges Faced

| Issue                     | Solution                         |
| ------------------------- | -------------------------------- |
| Permission Denied         | Used sudo privileges             |
| Duplicate Rules           | Implemented rule existence check |
| Invalid IP Formats        | Used ipaddress validation        |
| MongoDB Connection Errors | Added exception handling         |
| Continuous Loop Crash     | Added logging & safe shutdown    |

---

## 📚 11. Learning Outcomes

* Understanding automated security enforcement
* Linux firewall rule management
* Python subprocess handling
* Database-driven automation
* Real-time threat response mechanisms
* Defensive cybersecurity implementation

---

## ✅ 12. Conclusion

Week 3 successfully implemented a fully automated Dynamic Firewall Enforcement Engine.

The system:

* Monitors MongoDB for high-risk threats
* Automatically generates firewall rules
* Blocks malicious IP addresses
* Logs all actions
* Runs continuously as a daemon service

This completes the automated response layer of the Advanced Threat Intelligence Platform (TIP).

---

If you want next:

* 📄 Week 4 format
* 📊 Final project documentation
* 🎤 Viva questions
* 🧠 Architecture diagram explanation
* 📁 Final GitHub README full version

Bol do Sunny 😎🔥
