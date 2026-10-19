"""To spin up PhishGuard (web app + JSON API), run python app.py locally, or gunicorn app:app for production.""""
import os
import joblib, pandas as pd
from flask import Flask, jsonify, render_template, request
from phishguard import features

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
BASE = os.path.dirname(os.path.abspath(__file__))
_bundle = joblib.load(os.environ.get("MODEL_PATH", os.path.join(BASE, "models", "phishguard.joblib")))
MODEL, META = _bundle["model"], _bundle["meta"]
MAX_URL = 2048

def assess(url: str) -> dict:
    f = features.extract_features(url)
    row = pd.DataFrame([f])[features.FEATURE_NAMES]
    p = float(MODEL.predict_proba(row)[0][1])
    verdict = "phishing" if p >= 0.7 else "suspicious" if p >= 0.4 else "safe"
    return {"url": url, "verdict": verdict, "phishing_probability": round(p, 4),
            "reasons": features.explain(f), "model": META["best_model"]}

@app.get("/")
def index():
    return render_template("index.html", meta=META)

@app.post("/api/predict")
def api_predict():
    url = ((request.get_json(silent=True) or {}).get("url") or request.form.get("url") or "").strip()
    if not url or len(url) > MAX_URL:
        return jsonify(error=f"Provide a URL between 1 and {MAX_URL} characters."), 400
    return jsonify(assess(url))

@app.get("/api/health")
def health():
    return jsonify(status="ok", model=META["best_model"], data_source=META["data_source"])

@app.after_request
def secure(resp):
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"})
    return resp

if __name__ == "__main__":
    app.run(debug=False, port=5001)
