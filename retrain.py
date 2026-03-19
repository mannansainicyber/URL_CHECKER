import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import extract_features

DATASET_PATH = "dataset_phishing.csv"
MODEL_OUTPUT  = "model.pkl"

def load_and_extract(path):
    print("[*] loading dataset...")
    df = pd.read_csv(path)
    print(f"[*] {len(df)} rows found")

    print("[*] extracting features...")
    features = []
    for i, url in enumerate(df["url"]):
        if i % 1000 == 0:
            print(f"    {i}/{len(df)}")
        features.append(extract_features(str(url)))

    X = pd.DataFrame(features)
    y = (df["status"] == "phishing").astype(int)
    return X, y

def train(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_split=2,
        random_state=42,
        n_jobs=-1
    )

    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )

    print("[*] training ensemble (RF + GradientBoosting)...")
    model = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft",
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    print("\n[+] results on test set:")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))
    print("confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    return model

def save(model, path):
    joblib.dump(model, path)
    print(f"\n[+] model saved to {path}")

if __name__ == "__main__":
    X, y = load_and_extract(DATASET_PATH)
    model = train(X, y)
    save(model, MODEL_OUTPUT)