import datetime

def normalize_iocs(iocs):
    normalized = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }

    timestamp = datetime.datetime.now().isoformat()

    # Normalize IPs
    for ip in iocs["ips"]:
        normalized["ips"].append({
            "value": ip,
            "type": "ip",
            "source": "feed",
            "timestamp": timestamp
        })

    # Normalize Domains
    for domain in iocs["domains"]:
        normalized["domains"].append({
            "value": domain.lower(),
            "type": "domain",
            "source": "feed",
            "timestamp": timestamp
        })

    # Normalize URLs
    for url in iocs["urls"]:
        normalized["urls"].append({
            "value": url.lower(),
            "type": "url",
            "source": "feed",
            "timestamp": timestamp
        })

    # Normalize Hashes
    for h in iocs["hashes"]:
        normalized["hashes"].append({
            "value": h.lower(),
            "type": "hash",
            "source": "feed",
            "timestamp": timestamp
        })

    return normalized