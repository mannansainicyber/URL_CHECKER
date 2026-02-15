import uuid
import datetime
import pandas as pd
from features import extract_features
import hashlib
from .cache_manager import save_dump, find_in_dump  

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if url.endswith("/"):
        url = url[:-1]
    return url

def createlistreasonswf(features):
    reasons = []
    if features.get("has_ip_domain") == 1:
        reasons.append("URL contains an IP address in the domain")
    if features.get("has_at_symbol") == 1:
        reasons.append("URL contains '@' symbol")
    if features.get("special_char_ratio", 0) > 0.2:
        reasons.append("High ratio of special characters in URL")
    if features.get("path_length_ratio", 0) > 0.5:
        reasons.append("Excessively long path in URL")
    if features.get("query_length_ratio", 0) > 0.5:
        reasons.append("Excessively long query in URL")
    if features.get("contains_login") == 1:
        reasons.append("URL contains 'login'")
    if features.get("contains_verify") == 1:
        reasons.append("URL contains 'verify'")
    if features.get("contains_secure") == 1:
        reasons.append("URL contains 'secure'")
    if features.get("contains_update") == 1:
        reasons.append("URL contains 'update'")
    if features.get("contains_account") == 1:
        reasons.append("URL contains 'account'")
    return reasons

def predict_phishing(url: str, model):
    # Check if result is already in dump
    found = find_in_dump(url)
    if found:
        print(f"URL already processed: {url}")
        return found

    features = extract_features(url)
    df = pd.DataFrame([features])

    print(f"\nURL: {url}")
    print(f"FEATURES: {df.to_dict(orient='records')[0]}")

    proba = model.predict_proba(df)[0]
    phishing_score = float(proba[1])
    prediction = 1 if phishing_score >= 0.05 else 0
    confidence = phishing_score if prediction == 1 else 1 - phishing_score

    print(f"PROBABILITIES: {proba}")
    print(f"FINAL PREDICTION: {prediction}")

    result = {
        "UUID": str(uuid.uuid4()),
        "URL": url,
        "Features": df.to_dict(orient="records")[0],
        "phishing": prediction,
        "confidence": round(confidence, 3),
        "reasons": createlistreasonswf(df.to_dict(orient="records")[0]),
        "creation_day": str(datetime.datetime.now())
    }

    # Save result to dump
    normalized = normalize_url(url)
    url_hash = hashlib.sha256(normalized.encode()).hexdigest()
    save_dump(url_hash, result)  # ✅ Pass both arguments

    return result
