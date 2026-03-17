def normalize(data):
    normalized = []

    for d in data:
        indicator = d.get("indicator")

        # ❌ Skip empty values
        if not indicator:
            continue

        raw_type = str(d.get("type", "")).lower()
        tags = str(d.get("tags", "")).lower()

        # 🔥 PRIORITY: Detect C2 / Botnet
        if "c2" in tags or "botnet" in tags:
            ioc_type = "c2"
            severity = "critical"

        # 🎯 IOC Type Mapping
        elif "ip" in raw_type:
            ioc_type = "ip"
            severity = "high"

        elif "domain" in raw_type or "hostname" in raw_type:
            ioc_type = "domain"
            severity = "medium"

        elif "url" in raw_type:
            ioc_type = "url"
            severity = "medium"

        elif "hash" in raw_type or "md5" in raw_type or "sha" in raw_type:
            ioc_type = "hash"
            severity = "high"

        else:
            ioc_type = "unknown"
            severity = "low"

        normalized.append({
    "indicator": indicator,
    "type": ioc_type,
    "severity": severity,
    "source": d.get("source", "unknown"),   # ✅ keep source
    "tags": d.get("tags", [])               # ✅ keep tags
})

    return normalized