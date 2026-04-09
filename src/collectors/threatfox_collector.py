import requests
from src.collectors.base_collector import BaseCollector

class ThreatFoxCollector(BaseCollector):
    def __init__(self):
        super().__init__("ThreatFox")

    def fetch(self):
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {
            "query": "get_iocs",
            "limit": 50
        }
        # DO NOT add headers here. 401 means it thinks you are trying to auth without a key.
        headers = {
             "User-Agent": "Mozilla/5.0" 
        }

        indicators = []
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                if data.get("query_status") == "ok":
                    for item in data.get("data", []):
                        indicators.append({
                            "indicator": item.get("ioc_value"),
                            "type": item.get("ioc_type"),
                            "source": "ThreatFox",
                            "tags": item.get("tags", [])
                        })
                else:
                    print(f"ThreatFox API Status: {data.get('query_status')}")
            else:
                print(f"ThreatFox Error: {res.status_code} - {res.text}")

        except Exception as e:
            print("ThreatFox Request Error:", e)

        return indicators