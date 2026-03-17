from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

def get_collection():
    try:
        client = MongoClient(os.getenv("MONGO_URI"))
        client.admin.command('ping')  # ✅ checks connection

        db = client[os.getenv("DB_NAME")]
        return db["threat_indicators"]

    except Exception as e:
        print("MongoDB Error:", e)
        return None