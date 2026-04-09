import requests
from src.collectors.base_collector import BaseCollector


class PhishTankCollector(BaseCollector):

    def __init__(self):
        super().__init__("PhishTank")

    def fetch(self):
        # Using the developer API URL is often more stable than the bulk download
        url = "https://checkurl.phishtank.com/api/v2/"

        indicators = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntel/1.0"
        }

        # PhishTank API requires a format parameter
        params = {
            "format": "json",
            "app_key": "your_app_key_here" # PhishTank works without a key for limited checks, but if this fails, register one.
        }

        # NOTE: If the above API requires a key, use the CSV download fallback below instead:
        # url = "https://data.phishtank.com/data/online-valid.csv"
        # If you use CSV, you must parse CSV lines instead of JSON.

        # Let's stick to the CSV but with robust headers to fix your 404:
        url = "https://data.phishtank.com/data/online-valid.csv"

        try:
            res = requests.get(url, headers=headers, timeout=15)

            if res.status_code == 200:
                lines = res.text.split("\n")
                # Skip header
                for line in lines[1:50]: # Limit to 50
                    if not line.strip(): continue
                    parts = line.split(",")
                    if len(parts) > 1:
                        indicators.append({
                            "indicator": parts[1].strip('"'), # URL is usually 2nd column
                            "type": "url",
                            "source": "PhishTank"
                        })

            else:
                print(f"PhishTank Error: {res.status_code}")

        except Exception as e:
            print("PhishTank Request Error:", e)

        return indicators
