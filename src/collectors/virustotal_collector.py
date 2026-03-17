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
            "x-apikey": api_key
        }

        indicators = []

        # ✅ Use a known sample hash (free API works like this)
        sample_hashes = [
            "44d88612fea8a8f36de82e1278abb02f",  # test malware
            "eicar_test_file"
        ]

        for h in sample_hashes:
            url = f"https://www.virustotal.com/api/v3/files/{h}"

            try:
                res = requests.get(url, headers=headers)

                if res.status_code == 200:
                    indicators.append({
                        "indicator": h,
                        "type": "hash",
                        "source": "VirusTotal"
                    })

                else:
                    print(f"VT Error for {h}:", res.status_code)

            except Exception as e:
                print("VT Request Error:", e)

        return indicators