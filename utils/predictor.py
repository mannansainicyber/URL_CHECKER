import uuid, datetime
import pandas as pd
from features import extract_features

def createlistreasonswf(features):
    reasons = []
    if features["has_ip_domain"] == 1:
        reasons.append("URL contains an IP address in the domain")
    if features["has_at_symbol"] == 1:
        reasons.append("URL contains '@' symbol")
    if features["special_char_ratio"] > 0.2:
        reasons.append("High ratio of special characters in URL")
    if features["path_length_ratio"] > 0.5:
        reasons.append("Excessively long path in URL")
    if features["query_length_ratio"] > 0.5:
        reasons.append("Excessively long query in URL")
    if features["contains_login"] == 1:
        reasons.append("URL contains 'login'")
    if features["contains_verify"] == 1:
        reasons.append("URL contains 'verify'")
    if features["contains_secure"] == 1:
        reasons.append("URL contains 'secure'")
    if features["contains_update"] == 1:
        reasons.append("URL contains 'update'")
    if features["contains_account"] == 1:
        reasons.append("URL contains 'account'")
    return reasons
    

    

def predict_phishing(url: str, model):
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

    return {
        "UUID": str(uuid.uuid4()),
        "URL": url,
        "Features": df.to_dict(orient="records")[0],
        "phishing": prediction,
        "confidence": round(confidence, 3),
        "reasons": createlistreasonswf(df.to_dict(orient="records")[0]),
        "creation-day": datetime.datetime.now()
    }