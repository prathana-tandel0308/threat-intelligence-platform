from elasticsearch import Elasticsearch
from pymongo import MongoClient

# MongoDB connection
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client["threat_intel"]
collection = db["indicators"]

# Elasticsearch connection
es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "Y1g=sYZWh2ifzgvsygGv"),
    verify_certs=False
)

# Send data
for doc in collection.find():
    doc["_id"] = str(doc["_id"])
    es.index(index="threat-intel", document=doc)

print("✅ Data pushed to Elasticsearch")