from pymongo import MongoClient

print("RUNNING SCRIPT...")

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_db"]
collection = db["threats"]

data = [
    {"indicator": "192.168.1.1", "type": "ip", "severity": "high", "risk_score": 80},
    {"indicator": "malicious.com", "type": "domain", "severity": "critical", "risk_score": 95},
    {"indicator": "http://bad.com", "type": "url", "severity": "medium", "risk_score": 60},
    {"indicator": "abcd1234", "type": "hash", "severity": "low", "risk_score": 20}
]

collection.insert_many(data)

print("✅ Data inserted into MongoDB")