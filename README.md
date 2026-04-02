# 📌 Advanced Threat Intelligence Platform (TIP) & Dynamic Security Policy Enforcer

---

## 📖 Project Overview

### Project Title
Advanced Threat Intelligence Platform (TIP) with Dynamic Security Policy Enforcer  

### Domain
Finance & Banking Cybersecurity  

---

## 🎯 Objective

The objective of this project is to design and implement an automated cybersecurity defense system that can:

- Collect real-time threat intelligence from OSINT sources  
- Process and analyze threat data  
- Store and manage threat indicators centrally  
- Visualize threats using a SIEM dashboard  
- Automatically enforce firewall rules to block malicious activity  

The system minimizes manual intervention and enables proactive threat mitigation.

---

## ❗ Problem Statement

Financial institutions face continuous cyber threats such as:

- Advanced Persistent Threats (APT)  
- Zero-day attacks  
- Botnet traffic  
- Phishing infrastructures  

Traditional firewalls are static and cannot react quickly.

### Solution

This system solves the problem by:

- Collecting OSINT threat intelligence  
- Processing and analyzing indicators  
- Automatically blocking malicious IPs using firewall rules  

---

## 🚀 Key Features

- Automated OSINT threat data collection  
- Data cleaning, normalization, and deduplication  
- Risk scoring and severity classification  
- MongoDB-based centralized storage  
- ELK Stack integration (SIEM)  
- Real-time Kibana dashboard  
- Automated firewall enforcement using iptables  
- Logging and audit tracking  
- Reduced human intervention  

---

## 🏗️ System Architecture
OSINT Sources
↓
Threat Intelligence Collector (Python)
↓
Data Normalization & Processing
↓
MongoDB (Central Database)
↓
Elasticsearch (SIEM)
↓
Kibana Dashboard
↓
Dynamic Policy Enforcer (Firewall)
↓
iptables (Blocking Layer)

---

## 📦 Core Components

### 1. Threat Intelligence Collector
- Collects data from OSINT sources  
- Uses Python APIs  

**Sources:**
- AlienVault OTX  
- VirusTotal  
- AbuseIPDB  
- MalwareBazaar  
- PhishTank  
- ThreatFox  
- URLhaus  
- Feodo Tracker  

---

### 2. Data Normalization Engine
- Cleans raw data  
- Removes duplicates  
- Assigns risk scores  
- Classifies severity  

---

### 3. Database Layer (MongoDB)

```json
{
  "indicator_type": "IP",
  "value": "185.234.217.54",
  "source": "AlienVault",
  "risk_score": 92,
  "status": "active"
}
## 4. SIEM Integration (ELK Stack)

- **Elasticsearch** → Data indexing  
- **Logstash** → Data processing  
- **Kibana** → Visualization  

---

## 5. Dynamic Security Policy Enforcer

- Monitors MongoDB  
- Detects high-risk threats  
- Generates firewall rules  
- Blocks malicious IPs automatically  

---

## 6. Firewall Enforcement

Example rule:
iptables -A INPUT -s 185.234.217.54 -j DROP

---

## 7. Logging System

Logs include:

- Threat ingestion  
- Firewall actions  
- Blocked IPs  
- Timestamps  

---

## 📊 Key Performance Indicators (KPIs)

| KPI | Description |
|-----|------------|
| OSINT Integration | Connect to ≥ 3 threat sources |
| Processing Speed | < 10 seconds per data cycle |
| Duplicate Removal | No repeated indicators |
| Auto Blocking | High-risk IPs blocked automatically |
| Alert Generation | Real-time dashboard updates |

---

## 👥 User Personas

### SOC Analyst
- Monitors threats  
- Uses Kibana dashboard  

### Security Engineer
- Manages firewall rules  
- Verifies automated blocking  

### Compliance Officer
- Reviews logs  
- Ensures regulatory compliance  

---

