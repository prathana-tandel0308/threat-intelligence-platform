import time
from dotenv import load_dotenv
load_dotenv()

# Import all collectors
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
        AbuseIPDBCollector(),
        FeodoCollector(),
        PhishTankCollector(),
        ThreatFoxCollector(),
        URLHausCollector()
    ]

    data = []

    for c in collectors:
        try:
            result = c.fetch()
            if result:
                print(f"✅ {c.source}: {len(result)} indicators")
                data += result
            else:
                print(f"⚠️ {c.source}: No data returned (Check API errors above)")
        except Exception as e:
            print(f"❌ Error collecting from {c.source}: {e}")

    print(f"\nTotal Collected: {len(data)}")

    if not data:
        print("⚠️ No data collected in this cycle.")
        return

    # Process data
    data = normalize(data)
    data = remove_duplicates(data)

    print(f"After cleaning: {len(data)}")

    # Save to DB
    # FIX: We must use "is not None" for MongoDB collection objects
    db_collection = collectors[0].collection
    
    if db_collection is not None:
        try:
            collectors[0].save_indicators(data)
            print("✅ Stored in MongoDB")
        except Exception as e:
            print(f"❌ Database Error: {e}")
    else:
        print("❌ Database connection is None. Cannot save.")

def main():
    while True:
        try:
            run_pipeline()
            print("\n⏳ Waiting 5 minutes before next cycle...")
            time.sleep(1800)  
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping collector...")
            break
        except Exception as e:
            # Catch any unexpected crashes so the loop continues
            print(f"\n💥 Unexpected Critical Error: {e}")
            print("Restarting in 60 seconds...")
            time.sleep(1800) 

if __name__ == "__main__":
    main()
