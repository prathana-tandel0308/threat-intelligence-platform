def normalize(data):
    normalized = []

    for d in data:
        indicator = d.get("indicator")

        # ❌ Skip empty values
        if not indicator:
            continue

        indicator = str(indicator).strip().lower()
        raw_type = str(d.get("type", "")).lower()
        tags = str(d.get("tags", "")).lower()

        # 🔥 PRIORITY: Detect C2 / Botnet
        if "c2" in tags or "botnet" in tags:
            ioc_type = "c2"
            severity = "critical"
            risk_score = 90

        # 🎯 IOC Type Mapping
        elif "ip" in raw_type:
            ioc_type = "ip"
            severity = "high"
            risk_score = 70

        elif "domain" in raw_type or "hostname" in raw_type:
            ioc_type = "domain"
            severity = "medium"
            risk_score = 50

        elif "url" in raw_type:
            ioc_type = "url"
            severity = "medium"
            risk_score = 55

        elif "hash" in raw_type or "md5" in raw_type or "sha" in raw_type:
            ioc_type = "hash"
            severity = "high"
            risk_score = 75

        else:
            ioc_type = "unknown"
            severity = "low"
            risk_score = 20

        # ✅ CLEAN DATA (remove null-like values)
        cleaned_record = {
            "indicator": indicator,
            "type": ioc_type,
            "severity": severity,
            "risk_score": risk_score,
            "source": str(d.get("source", "unknown")).lower(),
            "tags": d.get("tags", []),
            "timestamp": str(d.get("timestamp", ""))
        }

        normalized.append(cleaned_record)

    return normalized