import requests
import os
from dotenv import load_dotenv
from src.collectors.base_collector import BaseCollector

load_dotenv()

class AlienVaultCollector(BaseCollector):
    def __init__(self):
        super().__init__("AlienVault")

    def fetch(self):
        # Reverted to 'subscribed' to fix 404 errors
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

        api_key = os.getenv("ALIENVAULT_API_KEY")

        headers = {
            "X-OTX-API-KEY": api_key.strip() if api_key else ""
        }

        try:
            res = requests.get(url, headers=headers, timeout=30)
        except Exception as e:
            print("Request Error:", e)
            return []

        indicators = []

        if res.status_code == 200:
            data = res.json()

            for pulse in data.get("results", []):
                for ind in pulse.get("indicators", []):
                    value = ind.get("indicator")
                    ind_type = str(ind.get("type", "")).lower()

                    if value and any(x in ind_type for x in ["ip", "domain", "url", "hash"]):
                        indicators.append({
                            "indicator": value,
                            "type": ind_type,
                            "tags": pulse.get("tags", [])
                        })
        else:
            print(f"AlienVault Error: {res.status_code} - {res.text}")

        return indicators
