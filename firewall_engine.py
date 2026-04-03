# firewall_engine.py

import time
import signal
import logging
from config import CHECK_INTERVAL, LOG_FILE
from database import monitor_database

running = True


def shutdown_handler(signum, frame):
    global running
    logging.info("Firewall engine shutting down safely...")
    running = False


def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


if __name__ == "__main__":
    setup_logging()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    logging.info("Dynamic Firewall Enforcement Engine Started")

    while running:
        monitor_database()
        time.sleep(CHECK_INTERVAL)

    logging.info("Firewall engine stopped.")
