import os
import json
from .url_handler import normalize_url
import hashlib
DUMP_FILE = "dump.json"


def save_dump(url_hash: str, result: dict):
    try:
        if os.path.exists(DUMP_FILE):
            with open(DUMP_FILE, "r") as f:
                existing_data = json.load(f)
        else:
            existing_data = []
    except json.JSONDecodeError:
        existing_data = []

    existing_data.append({
        "url_hash": url_hash,
        "phishing": result["phishing"],
        "confidence": result["confidence"]
    })

    with open(DUMP_FILE, "w") as f:
        json.dump(existing_data, f, indent=2)

def find_in_dump(url: str):
    if not os.path.exists(DUMP_FILE):
        return None

    try:
        with open(DUMP_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        return None

    # Normalize + hash input URL
    normalized = normalize_url(url)
    url_hash = hashlib.sha256(normalized.encode()).hexdigest()

    for entry in reversed(data):
        if entry.get("url_hash") == url_hash:
            return entry

    return None
