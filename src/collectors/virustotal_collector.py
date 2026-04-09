import requests
import os
from dotenv import load_dotenv
from src.collectors.base_collector import BaseCollector

load_dotenv()

class VirusTotalCollector(BaseCollector):
    def __init__(self):
        super().__init__("VirusTotal")

    def fetch(self):
        api_key = os.getenv("VIRUSTOTAL_API_KEY")

        headers = {
            "x-apikey": api_key,
            "User-Agent": "Mozilla/5.0" # VT also checks user agents sometimes
        }

        indicators = []

        # This is the EICAR test string. It is static.
        # To get dynamic data, you would need a Premium API key for "Intelligence Hunting".
        sample_hashes = [
            "44d88612fea8a8f36de82e1278abb02f"
        ]

        for h in sample_hashes:
            url = f"https://www.virustotal.com/api/v3/files/{h}"

            try:
                res = requests.get(url, headers=headers, timeout=10)

                if res.status_code == 200:
                    indicators.append({
                        "indicator": h,
                        "type": "hash"
                    })
                elif res.status_code == 401:
                    print("VT Error: Invalid API Key")
                elif res.status_code == 404:
                    print("VT Error: File not found (EICAR might be archived)")
                else:
                    print(f"VT Error: {res.status_code}")

            except Exception as e:
                print("VT Error:", e)

        return indicators
