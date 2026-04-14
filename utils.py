import ipaddress
import logging
import re
import os
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

LOG_DIR = "/var/log/threat_intelligence"
BLOCKED_IPS_FILE = os.path.join(LOG_DIR, "blocked_ips.log")
BLOCKED_DOMAINS_FILE = os.path.join(LOG_DIR, "blocked_domains.log")
BLOCKED_URLS_FILE = os.path.join(LOG_DIR, "blocked_urls.log")
BLOCKED_HASHES_FILE = os.path.join(LOG_DIR, "blocked_hashes.log")
BLOCKED_EMAILS_FILE = os.path.join(LOG_DIR, "blocked_emails.log")
BLOCKED_CIDRS_FILE = os.path.join(LOG_DIR, "blocked_cidrs.log")
BLOCKED_JA3_FILE = os.path.join(LOG_DIR, "blocked_ja3.log")
BLOCKED_CERTS_FILE = os.path.join(LOG_DIR, "blocked_certs.log")
BLOCKED_FILENAMES_FILE = os.path.join(LOG_DIR, "blocked_filenames.log")

# ============================================================================
# INITIALIZATION
# ============================================================================

def _ensure_log_dir():
    """Create log directory if it doesn't exist"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception as e:
        logging.error(f"Failed to create log directory: {e}")

# Ensure directory exists on import
_ensure_log_dir()

# ============================================================================
# IP VALIDATION
# ============================================================================

def is_valid_ip(ip):
    """Validate IPv4 or IPv6 address"""
    if not ip or not isinstance(ip, str):
        return False
    
    ip = ip.strip()
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_ipv4(ip):
    """Validate IPv4 address only"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return isinstance(addr, ipaddress.IPv4Address)
    except ValueError:
        return False

def is_valid_ipv6(ip):
    """Validate IPv6 address only"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False

# ============================================================================
# CIDR VALIDATION
# ============================================================================

def is_valid_cidr(cidr):
    """Validate CIDR notation (e.g., 192.168.1.0/24)"""
    if not cidr or not isinstance(cidr, str):
        return False
    
    cidr = cidr.strip()
    
    if '/' not in cidr:
        return False
    
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False

# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

def is_valid_domain(domain):
    """Validate domain name"""
    if not domain or not isinstance(domain, str):
        return False
    
    domain = domain.lower().strip()
    
    # Remove common prefixes
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    domain = domain.split("/")[0].split(":")[0].split("?")[0]
    
    if not domain or domain.startswith("."):
        return False
    
    # Domain regex pattern
    pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$'
    
    if not re.match(pattern, domain):
        return False
    
    # Check TLD length (min 2, max 63)
    tld = domain.split('.')[-1]
    if len(tld) < 2 or len(tld) > 63:
        return False
    
    return True

# ============================================================================
# URL VALIDATION
# ============================================================================

def is_valid_url(url):
    """Validate URL"""
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    
    # Must start with http:// or https://
    if not url.startswith("http://") and not url.startswith("https://"):
        return False
    
    # Extract domain and validate
    try:
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]
        return is_valid_domain(domain)
    except Exception:
        return False

# ============================================================================
# HASH VALIDATION
# ============================================================================

def is_valid_hash(hash_value, hash_type=None):
    """
    Validate hash value
    Supports: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)
    """
    if not hash_value or not isinstance(hash_value, str):
        return False
    
    hash_value = hash_value.strip().upper()
    
    hash_patterns = {
        'md5': r'^[A-F0-9]{32}$',
        'sha1': r'^[A-F0-9]{40}$',
        'sha256': r'^[A-F0-9]{64}$',
        'sha512': r'^[A-F0-9]{128}$'
    }
    
    if hash_type:
        hash_type = hash_type.lower()
        if hash_type in hash_patterns:
            return bool(re.match(hash_patterns[hash_type], hash_value))
        return False
    
    # Auto-detect hash type
    for h_type, pattern in hash_patterns.items():
        if re.match(pattern, hash_value):
            return True
    
    return False

def detect_hash_type(hash_value):
    """Detect hash type based on length"""
    if not hash_value:
        return None
    
    hash_value = hash_value.strip().upper()
    length = len(hash_value)
    
    hash_types = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512'
    }
    
    if length in hash_types:
        if is_valid_hash(hash_value):
            return hash_types[length]
    
    return None

# ============================================================================
# EMAIL VALIDATION
# ============================================================================

def is_valid_email(email):
    """Validate email address"""
    if not email or not isinstance(email, str):
        return False
    
    email = email.lower().strip()
    
    # Basic email pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, email):
        return False
    
    # Check domain part
    domain = email.split('@')[-1]
    if not is_valid_domain(domain):
        return False
    
    return True

# ============================================================================
# JA3 VALIDATION
# ============================================================================

def is_valid_ja3(ja3_value):
    """
    Validate JA3 fingerprint
    Can be raw JA3 string (numbers separated by commas) or MD5 hash (32 hex chars)
    """
    if not ja3_value or not isinstance(ja3_value, str):
        return False
    
    ja3_value = ja3_value.strip()
    
    # Check if it's a JA3 MD5 hash
    if re.match(r'^[A-Fa-f0-9]{32}$', ja3_value):
        return True
    
    # Check if it's raw JA3 string (numbers and commas)
    if re.match(r'^[\d,]+$', ja3_value):
        parts = ja3_value.split(',')
        # JA3 has typically 5 fields
        if len(parts) >= 5:
            return True
    
    return False

# ============================================================================
# CERTIFICATE VALIDATION
# ============================================================================

def is_valid_certificate_hash(cert_hash):
    """Validate SSL certificate hash (SHA1 or SHA256)"""
    if not cert_hash or not isinstance(cert_hash, str):
        return False
    
    cert_hash = cert_hash.strip().upper()
    
    # SHA1 (40 chars) or SHA256 (64 chars)
    if re.match(r'^[A-F0-9]{40}$', cert_hash):
        return True
    if re.match(r'^[A-F0-9]{64}$', cert_hash):
        return True
    
    return False

# ============================================================================
# FILENAME VALIDATION
# ============================================================================

def is_valid_filename(filename):
    """Validate filename (basic check)"""
    if not filename or not isinstance(filename, str):
        return False
    
    filename = filename.strip()
    
    # Remove path if present
    filename = filename.split('/')[-1].split('\\')[-1]
    
    if not filename:
        return False
    
    # Check for invalid characters (Windows)
    invalid_chars = r'[<>:"|?*\x00-\x1f]'
    if re.search(invalid_chars, filename):
        return False
    
    # Must have an extension
    if '.' not in filename:
        return False
    
    # Check length
    if len(filename) > 255:
        return False
    
    return True

# ============================================================================
# SAVE FUNCTIONS
# ============================================================================

def _save_to_log(filepath, indicator, extra_info=None):
    """Generic function to save indicator to log file"""
    try:
        _ensure_log_dir()
        timestamp = datetime.utcnow().isoformat()
        
        with open(filepath, 'a') as f:
            if extra_info:
                f.write(f"{timestamp} | {indicator} | {extra_info}\n")
            else:
                f.write(f"{timestamp} | {indicator}\n")
        return True
    except Exception as e:
        logging.error(f"Failed to save to {filepath}: {e}")
        return False

def save_blocked_ip(ip):
    """Save blocked IP to log file"""
    extra = None
    try:
        addr = ipaddress.ip_address(ip.strip())
        extra = f"version={addr.version}"
    except:
        pass
    return _save_to_log(BLOCKED_IPS_FILE, ip, extra)

def save_blocked_cidr(cidr):
    """Save blocked CIDR to log file"""
    return _save_to_log(BLOCKED_CIDRS_FILE, cidr)

def save_blocked_domain(domain):
    """Save blocked domain to log file"""
    return _save_to_log(BLOCKED_DOMAINS_FILE, domain)

def save_blocked_url(url):
    """Save blocked URL to log file"""
    return _save_to_log(BLOCKED_URLS_FILE, url)

def save_blocked_hash(hash_value):
    """Save blocked hash to log file"""
    hash_type = detect_hash_type(hash_value)
    extra = f"type={hash_type}" if hash_type else "type=unknown"
    return _save_to_log(BLOCKED_HASHES_FILE, hash_value.upper(), extra)

def save_blocked_email(email):
    """Save blocked email to log file"""
    return _save_to_log(BLOCKED_EMAILS_FILE, email)

def save_blocked_ja3(ja3_value):
    """Save blocked JA3 fingerprint to log file"""
    is_hash = bool(re.match(r'^[A-Fa-f0-9]{32}$', ja3_value.strip()))
    extra = "format=hash" if is_hash else "format=raw"
    return _save_to_log(BLOCKED_JA3_FILE, ja3_value, extra)

def save_blocked_certificate(cert_hash):
    """Save blocked certificate hash to log file"""
    cert_hash = cert_hash.strip().upper()
    length = len(cert_hash)
    cert_type = "SHA256" if length == 64 else "SHA1" if length == 40 else "unknown"
    return _save_to_log(BLOCKED_CERTS_FILE, cert_hash, f"type={cert_type}")

def save_blocked_filename(filename):
    """Save blocked filename to log file"""
    # Extract just filename from path
    clean_name = filename.split('/')[-1].split('\\')[-1]
    return _save_to_log(BLOCKED_FILENAMES_FILE, clean_name)

# ============================================================================
# UNIVERSAL VALIDATOR
# ============================================================================

def validate_indicator(indicator, ioc_type):
    """
    Universal validator for all indicator types
    Returns: (is_valid: bool, normalized_indicator: str)
    """
    if not indicator or not ioc_type:
        return False, None
    
    ioc_type = ioc_type.lower().strip()
    indicator = indicator.strip()
    
    validators = {
        'ip': (is_valid_ip, lambda x: x.strip()),
        'ipv4': (is_valid_ipv4, lambda x: x.strip()),
        'ipv6': (is_valid_ipv6, lambda x: x.strip()),
        'cidr': (is_valid_cidr, lambda x: x.strip()),
        'subnet': (is_valid_cidr, lambda x: x.strip()),
        'domain': (is_valid_domain, lambda x: x.lower().strip()),
        'hostname': (is_valid_domain, lambda x: x.lower().strip()),
        'url': (is_valid_url, lambda x: x.strip()),
        'uri': (is_valid_url, lambda x: x.strip()),
        'hash': (is_valid_hash, lambda x: x.upper().strip()),
        'md5': (lambda x: is_valid_hash(x, 'md5'), lambda x: x.upper().strip()),
        'sha1': (lambda x: is_valid_hash(x, 'sha1'), lambda x: x.upper().strip()),
        'sha256': (lambda x: is_valid_hash(x, 'sha256'), lambda x: x.upper().strip()),
        'sha512': (lambda x: is_valid_hash(x, 'sha512'), lambda x: x.upper().strip()),
        'file_hash': (is_valid_hash, lambda x: x.upper().strip()),
        'email': (is_valid_email, lambda x: x.lower().strip()),
        'ja3': (is_valid_ja3, lambda x: x.strip()),
        'ja3_hash': (is_valid_ja3, lambda x: x.strip()),
        'tls_fingerprint': (is_valid_ja3, lambda x: x.strip()),
        'certificate': (is_valid_certificate_hash, lambda x: x.upper().strip()),
        'cert': (is_valid_certificate_hash, lambda x: x.upper().strip()),
        'ssl_cert': (is_valid_certificate_hash, lambda x: x.upper().strip()),
        'filename': (is_valid_filename, lambda x: x.strip()),
        'file': (is_valid_filename, lambda x: x.strip()),
    }
    
    if ioc_type not in validators:
        logging.warning(f"Unknown IOC type for validation: {ioc_type}")
        return True, indicator  # Allow unknown types
    
    validator, normalizer = validators[ioc_type]
    normalized = normalizer(indicator)
    is_valid = validator(indicator)
    
    return is_valid, normalized

# ============================================================================
# STATISTICS
# ============================================================================

def get_blocked_counts():
    """Get count of blocked indicators by type"""
    counts = {}
    
    files = {
        'ips': BLOCKED_IPS_FILE,
        'domains': BLOCKED_DOMAINS_FILE,
        'urls': BLOCKED_URLS_FILE,
        'hashes': BLOCKED_HASHES_FILE,
        'emails': BLOCKED_EMAILS_FILE,
        'cidrs': BLOCKED_CIDRS_FILE,
        'ja3': BLOCKED_JA3_FILE,
        'certificates': BLOCKED_CERTS_FILE,
        'filenames': BLOCKED_FILENAMES_FILE
    }
    
    for name, filepath in files.items():
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    counts[name] = sum(1 for _ in f)
            else:
                counts[name] = 0
        except Exception:
            counts[name] = 0
    
    return counts

# ============================================================================
# TEST FUNCTION
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("UTILS.PY VALIDATION TESTS")
    print("=" * 60)
    
    test_cases = [
        ("IP", "192.168.1.1", is_valid_ip),
        ("IP", "8.8.8.8", is_valid_ip),
        ("IP", "invalid", is_valid_ip),
        ("IPv6", "2001:4860:4860::8888", is_valid_ipv6),
        ("CIDR", "192.168.1.0/24", is_valid_cidr),
        ("CIDR", "invalid/24", is_valid_cidr),
        ("Domain", "example.com", is_valid_domain),
        ("Domain", "evil-malware.xyz", is_valid_domain),
        ("Domain", "not valid!", is_valid_domain),
        ("URL", "https://example.com/path", is_valid_url),
        ("URL", "example.com", is_valid_url),
        ("Hash MD5", "44d88612fea8a8f36de82e1278abb02f", is_valid_hash),
        ("Hash SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", is_valid_hash),
        ("Hash Invalid", "notahash", is_valid_hash),
        ("Email", "user@example.com", is_valid_email),
        ("Email", "invalid@", is_valid_email),
        ("JA3 Hash", "769,47-53-5-10-49161-49162-49171-49172-49199-50215-50216-50217-0-11-10-35-23-13-5-51-45-43-21,0-5-10-11-23-35,29-23-24,0", is_valid_ja3),
        ("JA3 Raw", "67344858584938c4bd1d79c0e9caa695", is_valid_ja3),
        ("Cert SHA1", "D2B4E8E2C3F4A1B2C3D4E5F6A7B8C9D0E1F2A3B4", is_valid_certificate_hash),
        ("Filename", "malware.exe", is_valid_filename),
        ("Filename", "/path/to/evil.dll", is_valid_filename),
    ]
    
    for name, value, validator in test_cases:
        result = "✅" if validator(value) else "❌"
        display_val = value[:50] + "..." if len(value) > 50 else value
        print(f"{result} {name:15} | {display_val}")
    
    print("\n" + "=" * 60)
    print("HASH TYPE DETECTION")
    print("=" * 60)
    
    test_hashes = [
        "44d88612fea8a8f36de82e1278abb02f",
        "356a192b7913b04c54574d18c28d46e6395428ab",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ]
    
    for h in test_hashes:
        h_type = detect_hash_type(h)
        print(f"🔍 {h[:32]}... -> {h_type}")