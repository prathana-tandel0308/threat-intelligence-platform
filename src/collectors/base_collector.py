from src.database.mongodb_connector import get_collection
from datetime import datetime

class BaseCollector:
    def __init__(self, source):
        self.source = source
        self.collection = get_collection()

        if self.collection is None:
            print("❌ Database connection failed")

    def save_indicators(self, indicators):
        if self.collection is None:
            print("❌ Cannot save — DB not connected")
            return

        for ind in indicators:
            ind["source"] = self.source
            ind["timestamp"] = datetime.utcnow()

            self.collection.update_one(
                {
                    "indicator": ind.get("indicator"),
                    "type": ind.get("type")
                },
                {"$set": ind},
                upsert=True
            )