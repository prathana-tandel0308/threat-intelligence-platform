def normalize(data):
    return [
        {
            "indicator": d["indicator"],
            "type": d["type"].lower()
        }
        for d in data
    ]