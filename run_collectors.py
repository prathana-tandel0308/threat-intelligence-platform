import time
import random
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

from src.collectors.alienvault_collector import AlienVaultCollector
from src.collectors.virustotal_collector import VirusTotalCollector
from src.collectors.abuseipdb_collector import AbuseIPDBCollector
from src.collectors.feodo_collector import FeodoCollector
from src.collectors.phishtank_collector import PhishTankCollector
from src.collectors.threatfox_collector import ThreatFoxCollector
from src.collectors.urlhaus_collector import URLHausCollector

from src.processors.normalizer import normalize
from src.processors.deduplicator import remove_duplicates


def run_pipeline():
    print("\n🚀 Starting collection cycle...\n")

    collectors = [
        AlienVaultCollector(),
        VirusTotalCollector(),
        FeodoCollector(),
        PhishTankCollector(),
        ThreatFoxCollector(),
        URLHausCollector()
    ]

    # 🔥 Reduce AbuseIPDB usage
    if random.randint(1, 3) == 1:
        collectors.append(AbuseIPDBCollector())

    data = []

    for c in collectors:
        try:
            result = c.fetch()
            time.sleep(2)  # 🔥 avoid rate limit

            if result:
                print(f"✅ {c.source}: {len(result)} indicators")
                data += result
            else:
                print(f"⚠️ {c.source}: No data returned")

        except Exception as e:
            print(f"❌ Error from {c.source}: {e}")

    print(f"\nTotal Collected: {len(data)}")

    if not data:
        return

    data = normalize(data)
    data = remove_duplicates(data)

    print(f"After cleaning: {len(data)}")

    for item in data:
        item["date_added"] = datetime.utcnow()

    db_collection = collectors[0].collection

    if db_collection is not None:
        collectors[0].save_indicators(data)
        print("✅ Stored in MongoDB")


def main():
    while True:
        try:
            run_pipeline()
            print("\n⏳ Waiting 15 minutes...\n")
            time.sleep(900)

        except KeyboardInterrupt:
            print("\n🛑 Stopped")
            break

        except Exception as e:
            print("Error:", e)
            time.sleep(60)


if __name__ == "__main__":
    main()