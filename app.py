import os
import hashlib
import joblib
from flask import Flask, render_template, request, jsonify
from utils.cache_manager import find_in_dump, save_dump
from utils.predictor import predict_phishing

class PhishingService:
    """Handles URL processing and model interaction."""
    
    def __init__(self, model_path):
        self.model_path = os.path.abspath(model_path)
        self.model = self._load_model()

    def _load_model(self):
        print(f"LOADING MODEL FROM: {self.model_path}")
        return joblib.load(self.model_path)

    def normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        return url.rstrip("/")

    def get_url_hash(self, url: str) -> str:
        normalized = self.normalize_url(url)
        return hashlib.sha256(normalized.encode()).hexdigest()

    def predict(self, url: str):
        # 1. Check Cache
        cached = find_in_dump(url)
        if cached:
            return {
                "phishing": int(cached.get("phishing", 0)),
                "confidence": float(cached.get("confidence", 0.0)),
                "source": "cache"
            }

        # 2. Run Prediction
        result = predict_phishing(url, self.model)

        # 3. Save to Cache
        url_hash = self.get_url_hash(url)
        save_dump(url_hash, result)
        
        result["source"] = "model"
        return result

class PhishingWebApp:
    """The Flask Application wrapper."""
    
    def __init__(self, service: PhishingService):
        self.app = Flask(__name__)
        self.service = service
        self._setup_routes()

    def _setup_routes(self):
        self.app.add_url_rule("/", "index", self.index)
        self.app.add_url_rule("/predict", "predict", self.predict, methods=["POST"])

    def index(self):
        return render_template("index.html")

    def predict(self):
        try:
            data = request.get_json(force=True)
            url = data.get("url", "").strip()

            if not url:
                return jsonify({"error": "No URL provided"}), 400

            result = self.service.predict(url)
            return jsonify(result)

        except Exception as e:
            print(f"SERVER ERROR: {e}")
            return jsonify({"error": str(e)}), 500

    def run(self, host="0.0.0.0", port=5000, debug=True):
        self.app.run(host=host, port=port, debug=debug)

# Entry Point
if __name__ == "__main__":
    predictor_service = PhishingService("model.pkl")
    web_app = PhishingWebApp(predictor_service)
    web_app.run()