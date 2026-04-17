# check_db.py
import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["threat_db"]
collection = db["threats"]

print("=" * 60)
print("THREAT DATABASE BREAKDOWN")
print("=" * 60)

# Total count
total = collection.count_documents({})
print(f"\n📊 Total Indicators: {total}")

# Count by type
print("\n📋 By Type:")
pipeline = [
    {"$group": {"_id": "$type", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}}
]
for doc in collection.aggregate(pipeline):
    print(f"   {doc['_id']:15} : {doc['count']}")

# High risk by type (>= 80)
print("\n🔥 High Risk (>= 80) by Type:")
pipeline_high = [
    {"$match": {"risk_score": {"$gte": 80}}},
    {"$group": {"_id": "$type", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}}
]
for doc in collection.aggregate(pipeline_high):
    print(f"   {doc['_id']:15} : {doc['count']}")

# Already blocked
blocked = collection.count_documents({"blocked": True})
print(f"\n🚫 Already Blocked: {blocked}")

# Unblocked high risk
unblocked = collection.count_documents({
    "risk_score": {"$gte": 80},
    "blocked": {"$ne": True}
})
print(f"⏳ Pending Block: {unblocked}")

print("\n" + "=" * 60)