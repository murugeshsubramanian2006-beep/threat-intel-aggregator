def correlate_iocs(normalized_iocs):
    correlation = {}

    # Flatten all IOCs into one list
    all_iocs = []

    for category in normalized_iocs:
        for item in normalized_iocs[category]:
            all_iocs.append(item["value"])

    # Count occurrences
    for ioc in all_iocs:
        if ioc not in correlation:
            correlation[ioc] = 1
        else:
            correlation[ioc] += 1

    # Assign severity
    results = []

    for ioc, count in correlation.items():
        if count >= 3:
            severity = "HIGH"
        elif count == 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results.append({
            "ioc": ioc,
            "count": count,
            "severity": severity
        })

    return results