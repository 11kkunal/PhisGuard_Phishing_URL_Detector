# PhishGuard: Phishing URL Detection

Classifies a URL as **safe / suspicious / phishing** from lexical features alone (no page fetch, so no exposure to malicious content). Compares Naive Bayes, Decision Tree and k-NN, auto-selects the best by cross-validated F1, and serves it through a Flask UI and JSON API.

## Quick start
```bash
pip install -r requirements.txt
python build_dataset.py          # downloads real data (internet needed)
python train.py --data data/urls.csv
python app.py                    # http://127.0.0.1:5001
pytest                           # unit + API tests
docker build -t phishguard . && docker run -p 8000:8000 phishguard
```

## API
```bash
curl -X POST localhost:5001/api/predict -H 'Content-Type: application/json' \
     -d '{"url":"http://secure-paypal-login.xyz/verify"}'
# {"verdict":"phishing","phishing_probability":0.98,"reasons":[...],"model":"Decision Tree"}
```
`GET /api/health` reports model and data source.

## Features (25)
URL length, dot count, `@`, HTTPS, suspicious keywords, hyphens, digits and digit ratio, IP-as-host, subdomain count, host length, path length, query params, punycode, link shortener, risky TLD, host entropy, `//` in path, explicit port.

## Methodology
Stratified 80/20 split; 5-fold CV on the training set for model selection (F1, since phishing is the positive class and both precision and recall matter); the winner is refit on all data. k-NN uses standardized features. Per-model accuracy, precision, recall, F1, confusion counts and latency are saved to `models/metrics.json`.

## Data and methodology
`python build_dataset.py` downloads real public data: ~789k active phishing URLs (Phishing.Database) and ~32k non-phishing URLs (Citizen Lab test lists plus top-site homepages). The two sources differ in style (path length, trailing slashes), which let early models "cheat" at ~97% accuracy. The builder therefore canonicalizes URLs and matches both classes on path-length bucket and query presence, giving 65,552 balanced URLs.
Evaluation uses a hostname-grouped 80/20 split (the same site never appears in both train and test) and 5-fold grouped CV for model selection by F1.

## Results (held-out test set, real data)
| Model | Accuracy | Precision | Recall | F1 | CV F1 |
|---|---|---|---|---|---|
| Naive Bayes | 0.779 | 0.896 | 0.633 | 0.742 | 0.740 |
| Decision Tree | 0.827 | 0.874 | 0.764 | 0.816 | 0.814 |
| **k-NN (selected)** | 0.835 | 0.885 | 0.773 | 0.825 | 0.825 |

Exact figures are regenerated in `models/metrics.json` by `python train.py --data data/urls.csv`. A lexical-only model on matched data scores well below the 97%+ often published for unmatched datasets; these figures are deliberately conservative.

## Improving it further
Add a larger, more varied benign set (e.g. Tranco top sites with real deep links), plus domain age (WHOIS), DNS, TLS-certificate and page-content features. Retrain regularly as phishing patterns drift.

## Known limitations
- Ordinary-looking domains (e.g. a hacked legitimate site) are hard to catch from URL text, and most modern phishing uses HTTPS, so HTTPS is a weak signal.
- Lexical features only: no WHOIS age, DNS, TLS certificate or page-content signals.
- Attackers can adapt URL patterns; retrain regularly and monitor drift.
- Verdicts are probabilistic. Treat as one layer of defence, not a sole control.
- Add rate limiting and authentication (e.g. API keys) before exposing publicly.

## Layout
`phishguard/` features + data · `train.py` model comparison · `app.py` Flask UI/API · `tests/` · `Dockerfile`
