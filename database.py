# database.py

import pymongo
import logging
from config import MONGO_URI, DB_NAME, COLLECTION_NAME, RISK_THRESHOLD
from firewall import block_ip


def monitor_database():
    try:
        client = pymongo.MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        logging.info("Connected to MongoDB successfully")
    except Exception as e:
        logging.error(f"MongoDB connection failed: {e}")
        return

    logging.info("Monitoring threat indicators...")

    threats = collection.find({
        "risk_score": {"$gte": RISK_THRESHOLD},
        "status": "active"
    })

    for threat in threats:
        indicator_type = threat.get("indicator_type")
        value = threat.get("value")

        if indicator_type == "ip":
            block_ip(value)
        else:
            logging.warning(f"Unsupported indicator type: {indicator_type}")
            
