import time
from dotenv import load_dotenv
load_dotenv()

from src.collectors.alienvault_collector import AlienVaultCollector
from src.collectors.virustotal_collector import VirusTotalCollector
from src.collectors.abuseipdb_collector import AbuseIPDBCollector

from src.processors.normalizer import normalize
from src.processors.deduplicator import remove_duplicates


def main():
    # Initialize collectors
    alien = AlienVaultCollector()
    vt = VirusTotalCollector()
    abuse = AbuseIPDBCollector()

    data = []

    # Collect from AlienVault
    av_data = alien.fetch()
    data += av_data
    print("AlienVault:", len(av_data))

    # Collect from VirusTotal
    vt_data = vt.fetch()
    data += vt_data
    print("After VT:", len(data))

    # Collect from AbuseIPDB
    abuse_data = abuse.fetch()
    data += abuse_data
    print("After Abuse:", len(data))

    print(f"\nCollected {len(data)} indicators")

    # Normalize + Deduplicate
    data = normalize(data)
    data = remove_duplicates(data)

    print(f"After cleaning: {len(data)} indicators")

    # Save to MongoDB
    if data:
        alien.save_indicators(data)
        print("✅ Data stored in MongoDB")
    else:
        print("⚠️ No data to store")


# 🔁 AUTO RUN EVERY 5 MINUTES
if __name__ == "__main__":
    while True:
        print("\n🚀 Starting collection cycle...\n")
        main()
        print("\n⏳ Waiting 5 minutes...\n")
        time.sleep(300)  # 300 sec = 5 minutes