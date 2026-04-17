from src.collectors.alienvault_collector import AlienVaultCollector
from src.collectors.virustotal_collector import VirusTotalCollector
from src.collectors.abuseipdb_collector import AbuseIPDBCollector


def run_all_collectors():
    print("🚀 Running all collectors...")

    collectors = [
        AlienVaultCollector(),
        VirusTotalCollector(),
        AbuseIPDBCollector()
    ]

    all_data = []

    for collector in collectors:
        try:
            data = collector.fetch()
            print(f"{collector.source}: {len(data)} indicators")

            collector.save_indicators(data)
            all_data.extend(data)

        except Exception as e:
            print(f"Error in {collector.source}:", e)

    print(f"✅ Total collected: {len(all_data)}")