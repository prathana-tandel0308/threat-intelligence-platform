from elasticsearch import Elasticsearch, helpers
from pymongo import MongoClient
import sys
import time
import datetime

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "threat_db"
COLLECTION_NAME = "threats"

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASS = "6VnIzFqX*QltlQtCk0F9"
INDEX_NAME = "threat-intel"

# ------------------ MongoDB ------------------
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_client.server_info()
    db = mongo_client[DB_NAME]
    collection = db[COLLECTION_NAME]
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    sys.exit(1)

# ------------------ Elasticsearch ------------------
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

doc_count = collection.count_documents({})
print(f"📊 Found {doc_count} documents in MongoDB")

# ❌ REMOVE DELETE
# if es.indices.exists(index=INDEX_NAME):
#     es.indices.delete(index=INDEX_NAME)

# ✅ CREATE INDEX ONLY IF NOT EXISTS
if not es.indices.exists(index=INDEX_NAME):
    mapping = {
        "mappings": {
            "properties": {
                "indicator": {"type": "keyword"},
                "type": {"type": "keyword"},
                "source": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "risk_score": {"type": "integer"},
                "blocked": {"type": "boolean"},
                "timestamp": {"type": "date"}
            }
        }
    }
    es.indices.create(index=INDEX_NAME, **mapping)
    print(f"🆕 Created index: {INDEX_NAME}")
else:
    print(f"✅ Using existing index: {INDEX_NAME}")

# ------------------ SERIALIZER ------------------
def serialize(doc):
    for key, value in doc.items():
        if isinstance(value, datetime.datetime):
            doc[key] = value.isoformat()
    return doc

# ------------------ GENERATOR ------------------
def generate_docs():
    for doc in collection.find():
        try:
            doc = serialize(doc)

            clean_doc = {
                "indicator": str(doc.get("indicator", "")),
                "type": str(doc.get("type", "")),
                "source": str(doc.get("source", "")),
                "severity": str(doc.get("severity", "low")),
                "risk_score": int(doc.get("risk_score", 0)),
                "blocked": bool(doc.get("blocked", False)),
                "timestamp": doc.get("timestamp")
            }

            # 🔥 UNIQUE ID (prevents duplicates)
            doc_id = f"{clean_doc['indicator']}_{clean_doc['type']}"

            yield {
                "_op_type": "update",   # 🔥 IMPORTANT
                "_index": INDEX_NAME,
                "_id": doc_id,
                "doc": clean_doc,
                "doc_as_upsert": True  # 🔥 INSERT if not exists
            }

        except Exception as e:
            print(f"⚠️ Skipping document: {e}")

# ------------------ BULK INSERT ------------------
try:
    success, errors = helpers.bulk(es, generate_docs(), raise_on_error=False)
    print(f"✅ Success: {success}")
    print(f"❌ Failed: {len(errors)}")
except Exception as e:
    print(f"❌ Bulk indexing error: {e}")
    sys.exit(1)

# ------------------ REFRESH ------------------
es.indices.refresh(index=INDEX_NAME)
time.sleep(1)

count = es.count(index=INDEX_NAME)["count"]
print(f"🔍 Verified {count} documents in Elasticsearch")

print("✅ Data push complete!")
