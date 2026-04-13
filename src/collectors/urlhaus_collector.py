import requests
from src.collectors.base_collector import BaseCollector

class URLHausCollector(BaseCollector):
    def __init__(self):
        super().__init__("URLHaus")

    def fetch(self):
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        
        indicators = []
        headers = {
             "User-Agent": "Mozilla/5.0" 
        }

        try:
            res = requests.post(url, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                for item in data.get("urls", []):
                    indicators.append({
                        "indicator": item.get("url"),
                        "type": "url",
                        "source": "URLHaus"
                    })
            else:
                print(f"URLHaus Error: {res.status_code}")

        except Exception as e:
            print("URLHaus Request Error:", e)

        return indicators