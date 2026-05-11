from modules.parser import parse_iocs
from modules.normalizer import normalize_iocs
from modules.correlator import correlate_iocs
from modules.blocklist import generate_blocklists
from modules.reporter import generate_report
def main():
    file_path = "feeds/sample_feed.txt"

    print("\n[+] Loading feed...")
    
    iocs = parse_iocs(file_path)

    print("\n[+] Parsed IOCs:\n")

    for key, values in iocs.items():
        print(f"{key.upper()}:")
        for v in values:
            print(f"  - {v}")
        print()

    # 🔥 NORMALIZATION STEP
    normalized = normalize_iocs(iocs)

    print("\n[+] Normalized IOCs:\n")

    for category, items in normalized.items():
        print(f"{category.upper()}:")
        for item in items:
            print(f"  - {item}")
        print()

    
    correlated = correlate_iocs(normalized)

    print("\n[+] Correlation Results:\n")

    for item in correlated:
        print(f"{item['ioc']} -> Count: {item['count']} | Severity: {item['severity']}")
    
    
    generate_blocklists(normalized)
    generate_report(normalized, correlated)

if __name__ == "__main__":
    main()