import ipaddress
import re
from urllib.parse import urlparse


def validate_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def validate_domain(domain):

    pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.[A-Za-z]{2,})+$"
    )

    return bool(pattern.match(domain))


def validate_url(url):

    try:

        parsed = urlparse(url)

        return all([
            parsed.scheme,
            parsed.netloc
        ])

    except Exception:

        return False


def validate_hash(hash_value):

    md5_pattern = r"^[a-fA-F0-9]{32}$"
    sha1_pattern = r"^[a-fA-F0-9]{40}$"
    sha256_pattern = r"^[a-fA-F0-9]{64}$"

    return any([
        re.match(md5_pattern, hash_value),
        re.match(sha1_pattern, hash_value),
        re.match(sha256_pattern, hash_value)
    ])


def validate_email(email):

    pattern = re.compile(
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    )

    return bool(pattern.match(email))


def validate_iocs(iocs):

    valid_iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": [],
        "emails": []
    }

    invalid_count = 0

    # IPS

    for ip in iocs.get("ips", []):

        if validate_ip(ip):
            valid_iocs["ips"].append(ip)
        else:
            invalid_count += 1

    # DOMAINS

    for domain in iocs.get("domains", []):

        if validate_domain(domain):
            valid_iocs["domains"].append(domain)
        else:
            invalid_count += 1

    # URLS

    for url in iocs.get("urls", []):

        if validate_url(url):
            valid_iocs["urls"].append(url)
        else:
            invalid_count += 1

    # HASHES

    for h in iocs.get("hashes", []):

        if validate_hash(h):
            valid_iocs["hashes"].append(h)
        else:
            invalid_count += 1

    # EMAILS

    for email in iocs.get("emails", []):

        if validate_email(email):
            valid_iocs["emails"].append(email)
        else:
            invalid_count += 1

    return valid_iocs, invalid_count