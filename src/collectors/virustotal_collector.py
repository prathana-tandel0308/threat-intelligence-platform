import requests
import os
from dotenv import load_dotenv
from src.collectors.base_collector import BaseCollector

load_dotenv()

class VirusTotalCollector(BaseCollector):
    def __init__(self):
        super().__init__("VirusTotal")

    def fetch(self):
        url = "https://www.virustotal.com/api/v3/intelligence/search"

        headers = {
            "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
        }

        params = {
    "query": "type:ip",
    "limit": 10
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
                    "indicator": item["id"],
                    "type": "hash"
                })

        return indicators