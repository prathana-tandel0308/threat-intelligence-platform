import requests
import os
from dotenv import load_dotenv
from src.collectors.base_collector import BaseCollector

# Load environment variables
load_dotenv()


class AlienVaultCollector(BaseCollector):

    def __init__(self):
        super().__init__("AlienVault")

    def fetch(self):
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

        # 🔍 Debug: check API key
        api_key = os.getenv("ALIENVAULT_API_KEY")
        print("KEY:", api_key)

        # Headers with API key
        headers = {
            "X-OTX-API-KEY": api_key.strip() if api_key else ""
        }

        try:
            res = requests.get(url, headers=headers)
        except Exception as e:
            print("Request Error:", e)
            return []

        indicators = []

        if res.status_code == 200:
            data = res.json()

            for pulse in data.get("results", []):
                for ind in pulse.get("indicators", []):
                    if ind.get("indicator"):
                        indicators.append({
                            "indicator": ind.get("indicator"),
                            "type": ind.get("type")
                        })

        else:
            print("❌ AlienVault API Error:", res.status_code)

        return indicators