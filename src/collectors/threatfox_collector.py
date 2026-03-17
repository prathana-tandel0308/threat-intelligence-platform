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

        indicators = []

        try:
            res = requests.post(url, json=payload)

            if res.status_code == 200:
                data = res.json()

                for item in data.get("data", []):
                    indicators.append({
                        "indicator": item.get("ioc"),
                        "type": item.get("ioc_type"),
                        "source": "ThreatFox",
                        "tags": item.get("tags", [])
                    })

            else:
                print("ThreatFox Error:", res.status_code)

        except Exception as e:
            print("ThreatFox Request Error:", e)

        return indicators