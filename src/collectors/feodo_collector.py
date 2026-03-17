import requests
from src.collectors.base_collector import BaseCollector


class FeodoCollector(BaseCollector):

    def __init__(self):
        super().__init__("Feodo")

    def fetch(self):
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

        indicators = []

        try:
            res = requests.get(url)

            if res.status_code == 200:
                lines = res.text.split("\n")

                for line in lines:
                    if line and not line.startswith("#"):
                        parts = line.split(",")
                        ip = parts[1]

                        indicators.append({
                            "indicator": ip,
                            "type": "c2",
                            "source": "Feodo"
                        })

            else:
                print("Feodo Error:", res.status_code)

        except Exception as e:
            print("Feodo Request Error:", e)

        return indicators