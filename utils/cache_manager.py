import os
import json
from .url_handler import normalize_url

DUMP_FILE = "dump.json"


def save_dump(json_data):
    try:
        if os.path.exists(DUMP_FILE):
            with open(DUMP_FILE, "r") as f:
                existing_data = json.load(f)
        else:
            existing_data = []
    except json.JSONDecodeError:
        existing_data = []

    existing_data.append(json_data)
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

    norm = normalize_url(url)
    for entry in reversed(data):
        entry_url = entry.get("URL") or entry.get("url")
        if entry_url and normalize_url(entry_url) == norm:
            return entry
    return None