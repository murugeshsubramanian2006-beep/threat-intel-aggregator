import os

def generate_blocklists(normalized_iocs):
    os.makedirs("output", exist_ok=True)

    # File paths
    ip_file = "output/ip_blocklist.txt"
    domain_file = "output/domain_blocklist.txt"
    url_file = "output/url_blocklist.txt"
    hash_file = "output/hash_blocklist.txt"

    # Write IPs
    with open(ip_file, "w") as f:
        for item in normalized_iocs["ips"]:
            f.write(item["value"] + "\n")

    # Write Domains
    with open(domain_file, "w") as f:
        for item in normalized_iocs["domains"]:
            f.write(item["value"] + "\n")

    # Write URLs
    with open(url_file, "w") as f:
        for item in normalized_iocs["urls"]:
            f.write(item["value"] + "\n")

    # Write Hashes
    with open(hash_file, "w") as f:
        for item in normalized_iocs["hashes"]:
            f.write(item["value"] + "\n")

    print("\n[+] Blocklists generated in 'output/' folder")