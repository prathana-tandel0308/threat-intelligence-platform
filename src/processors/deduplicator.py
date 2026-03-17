def remove_duplicates(data):
    seen = set()
    unique = []

    for d in data:
        if d["indicator"] not in seen:
            unique.append(d)
            seen.add(d["indicator"])

    return unique