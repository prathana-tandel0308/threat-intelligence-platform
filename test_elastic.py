from elasticsearch import Elasticsearch

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "Y1g=sYZWh2ifzgvsygGv"),
    verify_certs=False
)

doc = {
    "indicator": "1.1.1.1",
    "type": "ip",
    "severity": "high",
    "risk_score": 90
}

res = es.index(index="threat-intel", document=doc)

print(res)