import os
import joblib
from flask import Flask, render_template, request, jsonify
from utils.url_handler import normalize_url
from utils.cache_manager import find_in_dump, save_dump
from utils.predictor import predict_phishing

app = Flask(__name__)

MODEL_PATH = os.path.abspath("model.pkl")
print("LOADING MODEL FROM:", MODEL_PATH)
model = joblib.load(MODEL_PATH)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        cached = find_in_dump(url)
        if cached is not None:
            return jsonify({
                "phishing": int(cached.get("phishing", 0)),
                "confidence": float(cached.get("confidence", 0.0))
            })

        result = predict_phishing(url, model)
        save_dump(result)

        return jsonify({
            "phishing": result["phishing"],
            "confidence": result["confidence"]
        })

    except Exception as e:
        print("SERVER ERROR:", str(e))
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
