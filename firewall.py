import subprocess
import logging
import re
import os
from pymongo import MongoClient
from datetime import datetime

from utils import is_valid_ip, save_blocked_ip

blocked_indicators = set()

# MongoDB connection
try:
    mongo_client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    threat_collection = mongo_client["threat_db"]["threats"]
except Exception as e:
    logging.error(f"MongoDB connection failed: {e}")
    threat_collection = None

# Configuration Files
HOSTS_FILE = "/etc/hosts"
SQUID_BLOCKLIST = "/etc/squid/blocked_urls.txt"
HASH_QUARANTINE_LIST = "/var/log/threat_hashes.log"
EMAIL_BLOCKLIST = "/etc/postfix/sender_blacklist"
JA3_BLOCKLIST = "/etc/suricata/ja3_blacklist.txt"
CERT_BLOCKLIST = "/etc/suricata/cert_blacklist.txt"

# Ensure directories exist
for path in ["/var/log", "/etc/squid", "/etc/postfix", "/etc/suricata"]:
    os.makedirs(path, exist_ok=True)

def block_ip(ip):
    """Block IP address using iptables"""
    if not is_valid_ip(ip):
        return
    if ip in blocked_indicators:
        return

    try:
        result = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=10
        )
        if result.returncode != 0:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, timeout=10
            )
            logging.info(f"🔥 [IPTABLES] Blocked IP: {ip}")
            save_blocked_ip(ip)
    except Exception as e:
        logging.error(f"iptables failed for {ip}: {e}")
    
    blocked_indicators.add(ip)
    _mark_blocked_in_db(ip, "ip")

def block_cidr(cidr):
    """Block CIDR range using iptables"""
    if cidr in blocked_indicators:
        return
    
    # Validate CIDR format
    cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    if not re.match(cidr_pattern, cidr):
        logging.warning(f"Invalid CIDR format: {cidr}")
        return

    try:
        result = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", cidr, "-j", "DROP"],
            capture_output=True, timeout=10
        )
        if result.returncode != 0:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", cidr, "-j", "DROP"],
                check=True, timeout=10
            )
            logging.info(f"🔥 [IPTABLES] Blocked CIDR Range: {cidr}")
    except Exception as e:
        logging.error(f"iptables CIDR failed for {cidr}: {e}")
    
    blocked_indicators.add(cidr)
    _mark_blocked_in_db(cidr, "cidr")

def block_domain(domain):
    """Block domain using /etc/hosts"""
    domain = domain.lower().strip()
    # Remove http/https prefix if present
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    
    if domain in blocked_indicators:
        return
    
    # Basic domain validation
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$', domain):
        logging.warning(f"Invalid domain format: {domain}")
        return

    try:
        with open(HOSTS_FILE, 'r') as f:
            if domain in f.read():
                blocked_indicators.add(domain)
                _mark_blocked_in_db(domain, "domain")
                return
                
        with open(HOSTS_FILE, 'a') as f:
            f.write(f"\n0.0.0.0 {domain} # Blocked by TIP\n")
            # Also block www variant
            if not domain.startswith("www."):
                f.write(f"0.0.0.0 www.{domain} # Blocked by TIP\n")
        logging.info(f"🔥 [HOSTS] Blocked Domain: {domain}")
    except Exception as e:
        logging.error(f"Hosts failed for {domain}: {e}")
        
    blocked_indicators.add(domain)
    _mark_blocked_in_db(domain, "domain")

def block_url(url):
    """Block URL/Domain using Squid proxy"""
    if url in blocked_indicators:
        return

    domain = url.replace("http://", "").replace("https://", "").split("/")[0].split("?")[0]
    
    try:
        os.makedirs("/etc/squid", exist_ok=True)
        
        with open(SQUID_BLOCKLIST, 'a') as f:
            f.write(f".{domain}\n")
            f.write(f"{domain}\n")
        
        # Try to reload squid if running
        result = subprocess.run(
            ["sudo", "squid", "-k", "reconfigure"],
            capture_output=True, timeout=10
        )
        if result.returncode == 0:
            logging.info(f"🔥 [SQUID] Blocked URL/Domain: {url}")
        else:
            logging.info(f"🔥 [SQUID FILE] Blocked URL/Domain: {url} (squid not running)")
    except FileNotFoundError:
        logging.info(f"🔥 [SQUID FILE] Blocked URL/Domain: {url} (squid not installed)")
    except Exception as e:
        logging.error(f"Squid failed for {url}: {e}")

    blocked_indicators.add(url)
    _mark_blocked_in_db(url, "url")

def handle_hash(hash_value):
    """Handle malicious file hashes - log for EDR/AV integration"""
    hash_value = hash_value.upper().strip()
    
    if hash_value in blocked_indicators:
        return
    
    # Validate hash format (MD5, SHA1, SHA256)
    hash_patterns = {
        'md5': r'^[A-F0-9]{32}$',
        'sha1': r'^[A-F0-9]{40}$',
        'sha256': r'^[A-F0-9]{64}$'
    }
    
    hash_type = None
    for h_type, pattern in hash_patterns.items():
        if re.match(pattern, hash_value):
            hash_type = h_type
            break
    
    if not hash_type:
        logging.warning(f"Invalid hash format: {hash_value}")
        return

    try:
        os.makedirs("/var/log", exist_ok=True)
        with open(HASH_QUARANTINE_LIST, 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} | {hash_type.upper()} | {hash_value}\n")
        
        # Try to create YARA rule for this hash
        _create_yara_rule(hash_value, hash_type)
        
        logging.info(f"🔥 [HASH-{hash_type.upper()}] Malicious Hash Quarantined: {hash_value[:16]}...")
    except Exception as e:
        logging.error(f"Hash handling failed: {e}")

    blocked_indicators.add(hash_value)
    _mark_blocked_in_db(hash_value, "hash")

def _create_yara_rule(hash_value, hash_type):
    """Create YARA rule for hash detection"""
    yara_dir = "/etc/yara/rules"
    yara_file = f"{yara_dir}/threat_hashes.yar"
    
    try:
        os.makedirs(yara_dir, exist_ok=True)
        
        rule_name = f"ThreatHash_{hash_value[:8]}"
        yara_rule = f'''
rule {rule_name} {{
    meta:
        description = "Malicious {hash_type.upper()} hash detected by TIP"
        hash_type = "{hash_type}"
        hash_value = "{hash_value}"
        date_added = "{datetime.utcnow().isoformat()}"
    condition:
        {hash_type} == "{hash_value}"
}}
'''
        
        # Check if rule already exists
        existing_content = ""
        if os.path.exists(yara_file):
            with open(yara_file, 'r') as f:
                existing_content = f.read()
        
        if rule_name not in existing_content:
            with open(yara_file, 'a') as f:
                f.write(yara_rule)
            logging.debug(f"Created YARA rule for {hash_value[:16]}...")
    except Exception as e:
        logging.debug(f"YARA rule creation failed: {e}")

def block_email(email):
    """Block malicious email addresses"""
    email = email.lower().strip()
    
    if email in blocked_indicators:
        return
    
    # Basic email validation
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        logging.warning(f"Invalid email format: {email}")
        return

    try:
        os.makedirs("/etc/postfix", exist_ok=True)
        
        with open(EMAIL_BLOCKLIST, 'a') as f:
            f.write(f"{email}\tREJECT\n")
        
        logging.info(f"🔥 [EMAIL] Blocked Email: {email}")
        
        # Try to reload postfix
        subprocess.run(
            ["sudo", "postfix", "reload"],
            capture_output=True, timeout=10
        )
    except FileNotFoundError:
        logging.info(f"🔥 [EMAIL FILE] Blocked Email: {email} (postfix not installed)")
    except Exception as e:
        logging.error(f"Email blocking failed: {email}: {e}")

    blocked_indicators.add(email)
    _mark_blocked_in_db(email, "email")

def block_filename(filename):
    """Block malicious filenames - log for monitoring"""
    filename = filename.strip()
    
    if filename in blocked_indicators:
        return
    
    try:
        log_file = "/var/log/threat_filenames.log"
        with open(log_file, 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} | {filename}\n")
        
        logging.info(f"🔥 [FILENAME] Malicious Filename Logged: {filename}")
    except Exception as e:
        logging.error(f"Filename logging failed: {e}")

    blocked_indicators.add(filename)
    _mark_blocked_in_db(filename, "filename")

def block_ja3(ja3_hash):
    """Block JA3 TLS fingerprint"""
    ja3_hash = ja3_hash.strip()
    
    if ja3_hash in blocked_indicators:
        return
    
    # JA3 hash is typically 32 chars MD5
    if not re.match(r'^[0-9,]+$', ja3_hash) and not re.match(r'^[A-Fa-f0-9]{32}$', ja3_hash):
        logging.warning(f"Invalid JA3 format: {ja3_hash[:20]}...")
        return

    try:
        os.makedirs("/etc/suricata", exist_ok=True)
        
        with open(JA3_BLOCKLIST, 'a') as f:
            f.write(f"{ja3_hash}\n")
        
        logging.info(f"🔥 [JA3] Blocked TLS Fingerprint: {ja3_hash[:20]}...")
    except Exception as e:
        logging.error(f"JA3 blocking failed: {e}")

    blocked_indicators.add(ja3_hash)
    _mark_blocked_in_db(ja3_hash, "ja3")

def block_certificate(cert_hash):
    """Block malicious SSL certificate"""
    cert_hash = cert_hash.upper().strip()
    
    if cert_hash in blocked_indicators:
        return
    
    try:
        os.makedirs("/etc/suricata", exist_ok=True)
        
        with open(CERT_BLOCKLIST, 'a') as f:
            f.write(f"{cert_hash}\n")
        
        logging.info(f"🔥 [CERT] Blocked Certificate: {cert_hash[:20]}...")
    except Exception as e:
        logging.error(f"Certificate blocking failed: {e}")

    blocked_indicators.add(cert_hash)
    _mark_blocked_in_db(cert_hash, "certificate")

def _mark_blocked_in_db(indicator, ioc_type):
    if threat_collection is None: return
    try:
        threat_collection.update_many(
            {"indicator": indicator, "type": ioc_type},
            {"$set": {
                "blocked": True, 
                "blocked_at": datetime.utcnow()  # 🔥 CRITICAL FOR AUTO-ROLLBACK!
            }}
        )
    except Exception:
        pass
# ✅ MASTER ROUTER - Handles ALL threat types
def block_threat(threat_type, indicator):
    """Route threats to appropriate blocking function"""
    
    threat_type = (threat_type or "").lower().strip()
    
    if not indicator:
        return
    
    # Normalize indicator
    indicator = indicator.strip()
    
    # Route to appropriate handler
    handlers = {
        "ip": block_ip,
        "ipv4": block_ip,
        "ipv6": lambda x: logging.info(f"⚠️ IPv6 blocking not implemented: {x}"),
        "cidr": block_cidr,
        "subnet": block_cidr,
        "domain": block_domain,
        "hostname": block_domain,
        "url": block_url,
        "uri": block_url,
        "link": block_url,
        "hash": handle_hash,
        "md5": handle_hash,
        "sha1": handle_hash,
        "sha256": handle_hash,
        "sha512": handle_hash,
        "file_hash": handle_hash,
        "email": block_email,
        "email_address": block_email,
        "sender": block_email,
        "filename": block_filename,
        "file_name": block_filename,
        "file": block_filename,
        "ja3": block_ja3,
        "ja3_hash": block_ja3,
        "tls_fingerprint": block_ja3,
        "certificate": block_certificate,
        "cert": block_certificate,
        "ssl_cert": block_certificate,
    }
    
    handler = handlers.get(threat_type)
    
    if handler:
        try:
            handler(indicator)
        except Exception as e:
            logging.error(f"Handler failed for {threat_type}:{indicator}: {e}")
    else:
        logging.warning(f"⚠️ Unknown threat type: {threat_type} for indicator: {indicator[:50]}...")
