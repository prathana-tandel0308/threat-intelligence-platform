def remove_duplicates(data):
    seen = set()
    unique = []

    for d in data:
        # Create a unique key based on indicator and type
        key = (d.get("indicator"), d.get("type"))

        if key in seen:
            continue

        seen.add(key)
        unique.append(d)

    return unique