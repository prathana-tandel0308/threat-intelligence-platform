import time
import signal
import sys
import subprocess
import pymongo
import logging
import ipaddress
from pathlib import Path

# ---------------- CONFIG ----------------
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "threat_db"
COLLECTION_NAME = "threat_indicators"

RISK_THRESHOLD = 80
CHECK_INTERVAL = 10
BLOCKED_IP_FILE = "blocked_ips.txt"

# ---------------- LOGGING ----------------
logging.basicConfig(
    filename="dynamic_firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------- GLOBAL VARIABLES ----------------
running = True


# ---------------- SIGNAL HANDLER ----------------
def shutdown_handler(signum, frame):
    global running
    logging.info("Firewall engine shutting down safely...")
    running = False


# ---------------- IP VALIDATION ----------------
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ---------------- PERSISTENT STORAGE ----------------
def load_blocked_ips():
    try:
        if Path(BLOCKED_IP_FILE).exists():
            with open(BLOCKED_IP_FILE, "r") as f:
                return set(line.strip() for line in f if line.strip())
        return set()
    except Exception as e:
        logging.error(f"Error loading blocked IPs: {e}")
        return set()


def save_blocked_ip(ip):
    try:
        with open(BLOCKED_IP_FILE, "a") as f:
            f.write(ip + "\n")
    except Exception as e:
        logging.error(f"Error saving blocked IP: {e}")


blocked_indicators = load_blocked_ips()


# ---------------- FIREWALL FUNCTIONS ----------------
def rule_exists(ip):
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-n"],
            capture_output=True,
            text=True
        )
        return ip in result.stdout
    except Exception as e:
        logging.error(f"Error checking rule existence: {e}")
        return False


def block_ip(ip):
    if not is_valid_ip(ip):
        logging.warning(f"Invalid IP skipped: {ip}")
        return

    if ip in blocked_indicators:
        logging.info(f"IP already recorded as blocked: {ip}")
        return

    if rule_exists(ip):
        logging.info(f"IP already blocked in firewall: {ip}")
        blocked_indicators.add(ip)
        return

    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    try:
        subprocess.run(command, check=True)
        logging.info(f"Blocked IP successfully: {ip}")

        blocked_indicators.add(ip)
        save_blocked_ip(ip)

    except subprocess.CalledProcessError as e:
        logging.error(f"Firewall execution failed: {e}")
    except Exception as e:
        logging.error(f"Unexpected error while blocking IP: {e}")


# ---------------- PROCESS INDICATOR ----------------
def process_indicator(indicator):
    indicator_type = indicator.get("indicator_type")
    value = indicator.get("value")

    if indicator_type == "ip":
        block_ip(value)

    elif indicator_type == "domain":
        logging.warning(f"Domain detected (manual DNS block required): {value}")

    elif indicator_type == "hash":
        logging.warning(f"Malicious file hash detected: {value}")

    else:
        logging.warning(f"Unknown indicator type: {indicator_type}")


# ---------------- DATABASE MONITOR ----------------
def monitor_database():
    try:
        client = pymongo.MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        logging.info("Connected to MongoDB successfully")
    except Exception as e:
        logging.error(f"MongoDB connection failed: {e}")
        sys.exit(1)

    global running

    logging.info("Dynamic Firewall Enforcement Engine Started")

    while running:
        try:
            threats = collection.find({
                "risk_score": {"$gte": RISK_THRESHOLD},
                "status": "active"
            })

            for threat in threats:
                process_indicator(threat)

        except Exception as e:
            logging.error(f"Database monitoring error: {e}")

        time.sleep(CHECK_INTERVAL)

    logging.info("Firewall engine stopped.")


# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    monitor_database()
