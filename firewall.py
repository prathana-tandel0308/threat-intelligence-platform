# firewall.py

import subprocess
import logging
from utils import is_valid_ip, save_blocked_ip

blocked_indicators = set()


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
    global blocked_indicators

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
