import requests
from src.collectors.base_collector import BaseCollector


class PhishTankCollector(BaseCollector):

    def __init__(self):
        super().__init__("PhishTank")

    def fetch(self):
        url = "https://data.phishtank.com/data/online-valid.json"

        indicators = []

        try:
            res = requests.get(url)

            if res.status_code == 200:
                data = res.json()

                for item in data[:50]:  # limit for performance
                    indicators.append({
                        "indicator": item.get("url"),
                        "type": "url",
                        "source": "PhishTank"
                    })

            else:
                print("PhishTank Error:", res.status_code)

        except Exception as e:
            print("PhishTank Request Error:", e)

        return indicators