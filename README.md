# URL Phishing Checker

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-Machine%20Learning-orange)
![License](https://img.shields.io/badge/License-Apache-lightgrey)

A lightweight, web-based tool that detects whether a URL is **likely phishing or safe** using a hybrid approach of Machine Learning (Random Forest/SVM) and heuristic rule-based analysis.

*Built for educational purposes and experimentation in cybersecurity and applied AI.*

---

## Overview

Phishing attacks often rely on visual deception and URL manipulation. This tool analyzes the structure and content of a URL to determine its malicious intent.

### Key Features
- **Real-time Analysis:** Accepts a URL and processes it instantly.
- **Hybrid Detection:** Combines ML probability with hard-coded security rules.
- **Explainability:** Returns a confidence score and human-readable reasons (e.g., "Suspicious keywords found").
- **Performance:** Caches results locally to reduce redundant processing.
- **API Support:** Includes a JSON endpoint for programmatic access.

---

## How It Works

1.  **Input:** User submits a URL via the UI or API.
2.  **Normalization:** The URL is cleaned and standard components are parsed.
3.  **Feature Extraction:** The system extracts numerical and categorical features (e.g., length, special char count, domain age).
4.  **Prediction:** * The **ML Model** calculates a probability score.
    * **Rule-based logic** scans for known red flags.
5.  **Output:** A JSON response is returned with the verdict and cached for future lookups.

---

## Tech Stack

* **Core:** Python 3.x
* **Web Framework:** Flask
* **Machine Learning:** scikit-learn, pandas, joblib
* **Architecture:** REST API + Simple HTML/CSS Frontend

---
## ⚠️ Disclaimer

* Educational Use Only: This tool does not guarantee 100% protection against phishing attacks.

* Predictions are probabilistic and based on the training data used.

* False positives (safe sites marked as phishing) and false negatives (phishing sites marked as safe) may occur.

* Do not rely on this tool as your sole security measure.
