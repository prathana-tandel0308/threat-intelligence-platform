def remove_duplicates(data):
    seen = set()
    unique = []

    for d in data:
        val = d.get("indicator")

        # ❌ skip empty / invalid values
        if not val:
            continue

        # ❌ skip duplicates
        if val in seen:
            continue

        seen.add(val)
        unique.append(d)

    return unique