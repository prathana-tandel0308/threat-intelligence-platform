def normalize(data):
    normalized = []

    for d in data:
        indicator = str(d.get("indicator", "")).strip().lower()
        raw_type = str(d.get("type", "")).lower()

        if not indicator:
            continue

        if "ip" in raw_type:
            ioc_type = "ip"
            severity = "high"
            risk_score = 70

        elif "domain" in raw_type:
            ioc_type = "domain"
            severity = "medium"
            risk_score = 50

        elif "url" in raw_type:
            ioc_type = "url"
            severity = "medium"
            risk_score = 55

        elif "hash" in raw_type:
            ioc_type = "hash"
            severity = "high"
            risk_score = 75

        else:
            ioc_type = "unknown"
            severity = "low"
            risk_score = 20

        normalized.append({
            "indicator": indicator,
            "type": ioc_type,
            "severity": severity,
            "risk_score": risk_score,
            "source": d.get("source", "unknown"),
            "tags": d.get("tags", [])
        })

    return normalized