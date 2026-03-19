import uuid
import datetime
import hashlib
import pandas as pd
from features import extract_features
from .cache_manager import save_dump, find_in_dump

REASON_RULES = [
    ("has_ip_domain",       lambda v: v == 1,   "IP address used as domain"),
    ("has_at_symbol",       lambda v: v == 1,   "@ symbol in URL"),
    ("special_char_ratio",  lambda v: v > 0.2,  "High special character ratio"),
    ("path_length_ratio",   lambda v: v > 0.5,  "Unusually long path"),
    ("query_length_ratio",  lambda v: v > 0.5,  "Unusually long query string"),
    ("domain_entropy",      lambda v: v > 3.5,  "High domain entropy (random-looking)"),
    ("subdomain_count",     lambda v: v > 2,    "Excessive subdomains"),
    ("abused_tld",          lambda v: v == 1,   "Commonly abused TLD (.tk/.ml etc)"),
    ("is_url_shortener",    lambda v: v == 1,   "URL shortener detected"),
    ("digit_ratio",         lambda v: v > 0.3,  "High digit ratio in domain"),
    *[(f"contains_{kw}", lambda v: v == 1, f"Contains keyword '{kw}'")
      for kw in ["login", "verify", "secure", "update", "account", "confirm", "banking", "password"]],
]

def _get_reasons(features: dict) -> list:
    return [msg for key, check, msg in REASON_RULES if check(features.get(key, 0))]

def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def _url_hash(url: str) -> str:
    return hashlib.sha256(_normalize_url(url).encode()).hexdigest()

def predict_phishing(url: str, model) -> dict:
    cached = find_in_dump(url)
    if cached:
        return cached

    features  = extract_features(url)
    df        = pd.DataFrame([features])
    proba     = model.predict_proba(df)[0]
    score     = float(proba[1])
    prediction = 1 if score >= 0.5 else 0
    confidence = score if prediction == 1 else 1 - score

    result = {
        "UUID":         str(uuid.uuid4()),
        "URL":          url,
        "features":     features,
        "phishing":     prediction,
        "confidence":   round(confidence, 3),
        "reasons":      _get_reasons(features),
        "timestamp":    str(datetime.datetime.now()),
    }

    save_dump(_url_hash(url), result)
    return result