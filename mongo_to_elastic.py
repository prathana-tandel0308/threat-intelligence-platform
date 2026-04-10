from elasticsearch import Elasticsearch, helpers
from pymongo import MongoClient
import sys

# ================================
# 🔹 Configuration
# ================================
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "threat_db"
COLLECTION_NAME = "threats"

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "6VnIzFqX*QltlQtCk0F9"
INDEX_NAME = "threat-intel"

# ================================
# 🔹 Connect to MongoDB
# ================================
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_client.server_info()  # Force connection check
    db = mongo_client[DB_NAME]
    collection = db[COLLECTION_NAME]
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    sys.exit(1)

# ================================
# 🔹 Connect to Elasticsearch
# ================================
try:
    es = Elasticsearch(
        ES_HOST,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,
        ssl_show_warn=False,
        request_timeout=60
    )
    if not es.ping():
        raise ConnectionError("Cannot ping Elasticsearch")
    print("✅ Connected to Elasticsearch")
except Exception as e:
    print(f"❌ Elasticsearch connection failed: {e}")
    sys.exit(1)

# ================================
# 🔹 Check Document Count
# ================================
doc_count = collection.count_documents({})
if doc_count == 0:
    print("⚠️ No documents found in MongoDB collection")
    sys.exit(0)
print(f"📊 Found {doc_count} documents in MongoDB")

# ================================
# 🔹 Create/Reset Index
# ================================
if es.indices.exists(index=INDEX_NAME):
    es.indices.delete(index=INDEX_NAME)
    print(f"🗑️ Deleted existing index: {INDEX_NAME}")

mapping = {
    "mappings": {
        "properties": {
            "indicator": {"type": "keyword"},
            "type": {"type": "keyword"},
            "source": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "risk_score": {"type": "integer"}
        }
    }
}

es.indices.create(index=INDEX_NAME, **mapping)  # Fixed: no body=
print(f"🆕 Created index: {INDEX_NAME}")

# ================================
# 🔹 Prepare Documents
# ================================
def generate_docs():
    for doc in collection.find():
        try:
            clean_doc = {
                "indicator": str(doc.get("indicator", "")),
                "type": str(doc.get("type", "")),
                "source": str(doc.get("source", "")),
                "severity": str(doc.get("severity", "low")),
                "risk_score": int(doc.get("risk_score", 0))
            }
            yield {
                "_index": INDEX_NAME,
                "_id": str(doc["_id"]),
                "_source": clean_doc
            }
        except Exception as e:
            print(f"⚠️ Skipping document: {e}")

# ================================
# 🔹 Bulk Indexing
# ================================
try:
    success, errors = helpers.bulk(es, generate_docs(), raise_on_error=False)
    print(f"✅ Success: {success}")
    print(f"❌ Failed: {len(errors)}")
    
    if errors:
        for err in errors[:5]:  # Show first 5 errors
            print(f"   Error: {err}")
except Exception as e:
    print(f"❌ Bulk indexing error: {e}")
    sys.exit(1)

# ================================
# 🔹 Verify Index
# ================================
count = es.count(index=INDEX_NAME)["count"]
print(f"🔍 Verified {count} documents in Elasticsearch")
print("✅ Data push complete!")
