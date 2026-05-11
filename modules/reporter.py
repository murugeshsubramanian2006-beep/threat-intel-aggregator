def generate_report(normalized_iocs, correlated_iocs):
    report_file = "output/threat_report.txt"

    total_ips = len(normalized_iocs["ips"])
    total_domains = len(normalized_iocs["domains"])
    total_urls = len(normalized_iocs["urls"])
    total_hashes = len(normalized_iocs["hashes"])

    high = []
    medium = []
    low = []

    for item in correlated_iocs:
        if item["severity"] == "HIGH":
            high.append(item["ioc"])
        elif item["severity"] == "MEDIUM":
            medium.append(item["ioc"])
        else:
            low.append(item["ioc"])

    with open(report_file, "w") as f:
        f.write("Threat Intelligence Report\n")
        f.write("="*30 + "\n\n")

        f.write(f"Total IPs: {total_ips}\n")
        f.write(f"Total Domains: {total_domains}\n")
        f.write(f"Total URLs: {total_urls}\n")
        f.write(f"Total Hashes: {total_hashes}\n\n")

        f.write("High Severity IOCs:\n")
        for i in high:
            f.write(f" - {i}\n")

        f.write("\nMedium Severity IOCs:\n")
        for i in medium:
            f.write(f" - {i}\n")

        f.write("\nLow Severity IOCs:\n")
        for i in low:
            f.write(f" - {i}\n")

    print("\n[+] Threat report generated: output/threat_report.txt")