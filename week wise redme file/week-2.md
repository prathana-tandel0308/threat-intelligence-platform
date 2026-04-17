# 🚀 Advanced Threat Intelligence Platform (TIP)

---

## 📌 Week 2: Elasticsearch & Kibana Visualization

### 📖 Description
This project implements a threat intelligence pipeline that collects, stores, processes, and visualizes cybersecurity threat data. The system integrates MongoDB for data storage, Elasticsearch for indexing and searching, and Kibana for visualization and analysis.

### 🎯 Objectives
- Collect threat intelligence data
- Store data in MongoDB
- Push data into Elasticsearch
- Visualize data using Kibana dashboards
- Analyze threat patterns (type, severity, source)

---

## 🛠️ Technologies Used
- *Python* – Data processing & scripting
- *MongoDB* – NoSQL database
- *Elasticsearch* – Search & indexing engine
- *Kibana* – Data visualization dashboard
- *OSINT Sources* – Threat data collection

---

## ⚙️ Setup Instructions

### 1️⃣ Install Dependencies
bash
pip install pymongo elasticsearch


### 2️⃣ Start Services
bash
sudo systemctl start elasticsearch
sudo systemctl start kibana

(Note for Windows: You would run elasticsearch.bat and kibana.bat from their respective bin folders).

### 3️⃣ Run Script
bash
python3 mongo_to_elastic.py


### 4️⃣ Open Kibana
Navigate your browser to:
url
http://localhost:5601


### 5️⃣ Create Data View
Create a new index pattern using:
text
threat-intel*


---

## 🔄 Data Flow
text
MongoDB  →  Elasticsearch  →  Kibana Dashboard


## 📊 Visualizations Created
- 📊 *Bar Chart* – Threat Type Analysis
- 🟠 *Pie Chart* – Threat Source Distribution
- 📋 *Data Table* – Threat Details
- 🔢 *Metric* – Total Threat Count

## 📈 Key Insights
- Most threats are IP-based.
- Data is primarily sourced from comprehensive OSINT platforms.
- High severity threats are successfully grouped and identified using the unified risk score.
- The dashboard enables quick real-time threat analysis for security teams.

---

## ⚠️ Challenges Faced
- Elasticsearch connection issues (TLS warnings).
- Version mismatch (client vs server).
- Data mapping and indexing errors.
- Missing fields mapping (type vs indicator_type, timestamp tracking).

## ✅ Solutions
- Installed correct elasticsearch library version matching the server requirements.
- Used dynamic mapping safely through the Bulk helper API.
- Cleaned and normalized data before indexing via pipeline structures.
- Unified missing fields cleanly in the Python script.

## 🚀 Outcome
Successfully built a working threat intelligence pipeline capable of extracting database collections natively into ElasticSearch, unlocking real-time visualization and deep analysis using Kibana dashboards.
