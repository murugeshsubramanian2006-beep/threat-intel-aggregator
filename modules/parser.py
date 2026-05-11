import re

# Regex patterns
IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
URL_PATTERN = r'https?://[^\s]+'
HASH_PATTERN = r'\b[a-fA-F0-9]{32,64}\b'


def parse_iocs(file_path):
    import re

    IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    URL_PATTERN = r'https?://[^\s]+'
    HASH_PATTERN = r'\b[a-fA-F0-9]{32,64}\b'

    iocs = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "hashes": set()
    }

    try:
        with open(file_path, 'r') as file:
            for line in file:   # ✅ THIS WAS MISSING
                line = line.strip()

                iocs["ips"].update(re.findall(IP_PATTERN, line))
                iocs["domains"].update(re.findall(DOMAIN_PATTERN, line))
                iocs["urls"].update(re.findall(URL_PATTERN, line))
                iocs["hashes"].update(re.findall(HASH_PATTERN, line))

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")

    return iocs