import pytest
from phishguard.features import extract_features, FEATURE_NAMES

def test_feature_set_complete():
    assert list(extract_features("https://example.com").keys()) == FEATURE_NAMES

def test_core_signals():
    f = extract_features("http://paypal.com@192.168.1.1/login/verify")
    assert f["has_at"] == 1 and f["is_https"] == 0 and f["has_ip_host"] == 1
    assert f["num_suspicious_keywords"] >= 3

def test_dots_and_https():
    f = extract_features("https://a.b.example.com/x")
    assert f["num_dots"] == 3 and f["is_https"] == 1 and f["num_subdomains"] == 2

@pytest.mark.parametrize("bad", ["", "http://", "http://[::1", "x" * 5000, "http://a:99999999/"])
def test_robust_to_garbage(bad):
    extract_features(bad)

def test_trailing_slash_is_ignored():
    assert extract_features("https://a.com/") == extract_features("https://a.com")

def test_api():
    import app as a
    c = a.app.test_client()
    assert c.get("/api/health").status_code == 200
    assert c.post("/api/predict", json={"url": ""}).status_code == 400
    bad = c.post("/api/predict", json={"url": "http://paypal.com.secure-login.weebly.com/verify/account.php?id=88231"}).get_json()
    assert bad["verdict"] == "phishing" and bad["reasons"]
    good = c.post("/api/predict", json={"url": "https://en.wikipedia.org/wiki/Phishing"}).get_json()
    assert good["verdict"] == "safe"
    assert 0 <= good["phishing_probability"] <= 1
