import requests
import os
from dotenv import load_dotenv
from src.collectors.base_collector import BaseCollector

load_dotenv()

class AbuseIPDBCollector(BaseCollector):
    def __init__(self):
        super().__init__("AbuseIPDB")

    def fetch(self):
        url = "https://api.abuseipdb.com/api/v2/blacklist"

        headers = {
            "Key": os.getenv("ABUSEIPDB_API_KEY"),
            "Accept": "application/json"
        }

        params = {
            "confidenceMinimum": 90
        }

        try:
            res = requests.get(url, headers=headers, params=params)
        except Exception as e:
            print("Error:", e)
            return []

        indicators = []

        if res.status_code == 200:
            for item in res.json().get("data", []):
                indicators.append({
                    "indicator": item["ipAddress"],
                    "type": "ip"
                })

        return indicators