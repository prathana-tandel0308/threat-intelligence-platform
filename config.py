# config.py

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "threat_db"
COLLECTION_NAME = "threat_indicators"

RISK_THRESHOLD = 80
CHECK_INTERVAL = 10

BLOCKED_IP_FILE = "blocked_ips.txt"
LOG_FILE = "dynamic_firewall.log"
