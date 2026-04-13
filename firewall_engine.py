import time
import signal
import sys
import pymongo
import logging
from datetime import datetime, timedelta
import subprocess

from firewall import block_threat

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "threat_db"
COLLECTION_NAME = "threats"

RISK_THRESHOLD = 80
CHECK_INTERVAL = 15
ROLLBACK_HOURS = 24  # Auto-unblock after 24 hours

logging.basicConfig(
    filename="dynamic_firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.getLogger().addHandler(console_handler)

running = True

def shutdown_handler(signum, frame):
    global running
    logging.info("Shutting down firewall engine...")
    running = False

def auto_rollback(collection):
    """Safety Feature: Automatically unblock indicators older than ROLLBACK_HOURS"""
    threshold_time = datetime.utcnow() - timedelta(hours=ROLLBACK_HOURS)

    docs = collection.find({
        "blocked": True,
        "blocked_at": {"$lte": threshold_time}
    })

    count = 0
    for doc in docs:
        indicator = doc["indicator"]
        ioc_type = doc["type"]
        
        # System level unblock
        if ioc_type == "ip":
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", indicator, "-j", "DROP"], capture_output=True)
        
        # Update DB
        collection.update_one(
            {"indicator": indicator, "type": ioc_type},
            {"$set": {"blocked": False, "rollback_at": datetime.utcnow(), "auto_rollback": True}}
        )
        logging.info(f"⏳ Auto rollback: {indicator}")
        count += 1
        
    if count > 0:
        logging.info(f"🧹 Auto-rollback completed for {count} expired indicator(s)")

def monitor_database():
    try:
        client = pymongo.MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        logging.info("Connected to MongoDB")
    except Exception as e:
        logging.error(f"MongoDB failed: {e}")
        sys.exit(1)

    global running
    logging.info(f"Firewall Engine Started (Threshold >= {RISK_THRESHOLD})")
    logging.info(f"Safety Control: Auto-Rollback active ({ROLLBACK_HOURS}h limit)")

    while running:
        try:
            # 1. RUN AUTO-ROLLBACK SAFETY CHECK
            auto_rollback(collection)

            # 2. FETCH AND BLOCK NEW THREATS
            query = {
                "type": {"$in": ["ip", "domain", "url", "hash", "email", "cidr", "filename", "ja3", "certificate"]}, 
                "risk_score": {"$gte": RISK_THRESHOLD},
                "blocked": {"$ne": True}
            }

            threats = list(collection.find(query))

            if threats:
                logging.info(f"🚨 Found {len(threats)} new high-risk indicator(s) to block")
                for threat in threats:
                    indicator = threat.get("indicator")
                    ioc_type = threat.get("type")
                    block_threat(ioc_type, indicator)

        except Exception as e:
            logging.error(f"DB error: {e}")

        time.sleep(CHECK_INTERVAL)

    logging.info("Firewall stopped")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    monitor_database()
