# utils.py

import logging
import ipaddress
from pathlib import Path
from config import BLOCKED_IP_FILE


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


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
