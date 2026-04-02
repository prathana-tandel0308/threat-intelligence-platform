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

## 🏗️ System Flow
1. OSINT Sources  
2. Threat Intelligence Collector (Python)  
3. Data Normalization & Processing  
4. MongoDB (Central Database)  
5. Elasticsearch (SIEM)  
6. Kibana Dashboard  
7. Dynamic Policy Enforcer (Firewall)  
8. iptables (Blocking Layer) 

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

### Example Threat Record (MongoDB)

- Indicator Type: IP  
- Value: 185.234.217.54  
- Source: AlienVault  
- Risk Score: 92  
- Status: active  

---

### 4. SIEM Integration (ELK Stack)

- **Elasticsearch** → Data indexing  
- **Logstash** → Data processing  
- **Kibana** → Visualization  

---

### 5. Dynamic Security Policy Enforcer

- Monitors MongoDB  
- Detects high-risk threats  
- Generates firewall rules  
- Blocks malicious IPs automatically  

