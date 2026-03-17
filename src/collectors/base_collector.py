from src.database.mongodb_connector import get_collection
from datetime import datetime

class BaseCollector:
    def __init__(self, source):
        self.source = source
        self.collection = get_collection()

        if self.collection is None:
            print("❌ Database connection failed")

    def save_indicators(self, indicators):
        for ind in indicators:
            ind["source"] = self.source
            ind["timestamp"] = datetime.utcnow()

            self.collection.update_one(
                {
                    "indicator": ind["indicator"],
                    "type": ind["type"]
                },
                {"$set": ind},
                upsert=True
            )