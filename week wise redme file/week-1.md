# 🚀 Advanced Threat Intelligence Platform (TIP)

---

## 📌 Week 1: Threat Intelligence Feed Integration

### 🎯 Objective
The objective of Week 1 was to set up the development environment and implement automated threat intelligence collection from multiple OSINT (Open Source Intelligence) sources.

---

## 🧰 1. Environment Setup

The project was configured on a Windows system.

### Tools Installed:
- Python 3.x  
- MongoDB (local database)  
- Git (version control)  
- VS Code (code editor)  

### Python Libraries:
```bash
pip install requests pymongo python-dotenv
```

## 📁 2. Project Structure
```text
threat-intelligence-platform/
│
├── src/
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base_collector.py
│   │   ├── alienvault_collector.py
│   │   ├── abuseipdb_collector.py
│   │   ├── virustotal_collector.py
│   │   ├── phishtank_collector.py
│   │   ├── threatfox_collector.py
│   │   ├── urlhaus_collector.py
│   │   └── feodo_collector.py
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   └── mongodb_connector.py
│   │
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── normalizer.py
│   │   └── deduplicator.py
│
├── docs/
│   └── week1_report.pdf
│
├── assets/
│   └── screenshots.png
│
├── run_collectors.py
├── .env
├── requirements.txt
├── README.md
└── .gitignore
```

## 🗄 3. MongoDB Integration
MongoDB is used to store threat indicators.

### Database Details:
- **Database**: `threat_db` *(Note: Unified to `threat_intel` in later phases)*
- **Collection**: `threats` *(Note: Unified to `indicators` in later phases)*

### Features:
- Stores IPs, domains, hashes
- Fast querying
- Deduplication using `update_one()`

## 🌐 4. OSINT API Integration
**Integrated Sources:**
- AlienVault OTX
- VirusTotal
- AbuseIPDB

**Data Collected:**
- Malicious IP addresses
- Domains
- URLs
- File hashes

## ⚙️ 5. Collector Implementation
Each OSINT source has its own collector module.

### Flow:
1. Connect to API
2. Fetch data
3. Extract indicators
4. Format data
5. Store in database

## 💾 6. Data Storage Logic
```python
collection.update_one(
    {"indicator": ind["indicator"], "type": ind["type"]},
    {"$set": ind},
    upsert=True
)
```
### Benefits:
- Prevents duplicate entries
- Updates existing records

## ▶️ 7. Execution Script
The main script `run_collectors.py`:
- Runs all collectors
- Collects data from APIs
- Processes data
- Stores data in MongoDB
- Runs continuously

## 📊 8. Output Example
```text
🚀 Starting collection cycle...
AlienVault: 132
VirusTotal: 1
AbuseIPDB: 0
Collected: 133
After cleaning: 133
✅ Stored in MongoDB
```

## ⚠️ 9. Challenges Faced
| Issue | Solution |
|-------|----------|
| API Errors (401/403) | Fixed API keys in `.env` |
| Duplicate Data | Used MongoDB `update_one()` |
| Infinite Loop | Controlled execution |
| Database Errors | Corrected DB configuration |

## 📚 10. Learning Outcomes
- Understanding OSINT threat intelligence
- API integration using Python
- MongoDB database handling
- Data collection automation
- Basic cybersecurity concepts

## ✅ 11. Conclusion
Week 1 successfully implemented a working threat intelligence collection system. The platform automatically collects and stores threat indicators from multiple OSINT sources, forming the foundation for further development.

---

## ⚙️ RUNNING STEPS (WINDOWS)

### 🟢 1. Open Project Folder
```bash
cd C:\threat-intelligence-platform
```

### 🟢 2. Install Requirements
```bash
pip install -r requirements.txt
```

### 🟢 3. Setup .env
```env
MONGO_URI=mongodb://localhost:27017/
DB_NAME=threat_intel

ALIENVAULT_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```

### 🟢 4. Start MongoDB
```bash
mongod
```

### 🟢 5. Run Project
```bash
python run_collectors.py
```

### 🟢 6. Expected Output
```text
🚀 Starting collection cycle...
...
✅ Stored in MongoDB
```

### 🟢 7. Verify in MongoDB
```bash
mongosh
use threat_intel
db.indicators.find().pretty() 
```
