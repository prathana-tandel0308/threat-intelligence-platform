from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

def get_collection():
    try:
        mongo_uri = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
        db_name = os.getenv("DB_NAME") or "threat_db"

        client = MongoClient(mongo_uri)
        client.admin.command('ping')

        db = client[db_name]

        return db["threats"]   # ✅ use ONE collection only

    except Exception as e:
        print("MongoDB Error:", e)
        return None