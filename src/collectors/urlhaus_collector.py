import requests
from src.collectors.base_collector import BaseCollector


class URLHausCollector(BaseCollector):

    def __init__(self):
        super().__init__("URLHaus")

    def fetch(self):
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

        indicators = []

        try:
            res = requests.get(url)

            if res.status_code == 200:
                data = res.json()

                for item in data.get("urls", []):
                    indicators.append({
                        "indicator": item.get("url"),
                        "type": "url",
                        "source": "URLHaus"
                    })

            else:
                print("URLHaus Error:", res.status_code)

        except Exception as e:
            print("URLHaus Request Error:", e)

        return indicators