def remove_duplicates(data):
    seen = set()
    unique = []

    for d in data:
        indicator = d.get("indicator")
        ioc_type = d.get("type")

        # ❌ skip empty
        if not indicator:
            continue

        # ✅ create unique key
        key = (indicator, ioc_type)

        # ❌ skip duplicates
        if key in seen:
            continue

        seen.add(key)
        unique.append(d)

    return unique