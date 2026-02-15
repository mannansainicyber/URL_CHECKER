import joblib
import pandas as pd
from features import extract_features

model = joblib.load("model.pkl")

tests = [
    "http://paypal-login-verification.example",
    "http://secure-login.paypal.account.verify.user.session.example",
    "https://google.com"
]

for url in tests:
    features = extract_features(url)
    df = pd.DataFrame([features])

    pred = model.predict(df)[0]

    if hasattr(model, "predict_proba"):
        prob = model.predict_proba(df)[0]
    else:
        prob = "NO_PROBA"

    print("\nURL:", url)
    print("Prediction:", pred)
    print("Probabilities:", prob)

