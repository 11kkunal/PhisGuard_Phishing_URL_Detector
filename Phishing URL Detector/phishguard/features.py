from __future__ import annotations
import math, re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "bank", "confirm",
    "password", "paypal", "wallet", "billing", "support", "suspend", "unlock", "invoice",
)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "icu", "zip", "rest"}
FREE_HOSTS = ("weebly.com", "wixsite.com", "webhostapp.com", "blogspot.com", "github.io", "pages.dev", "web.app",
              "firebaseapp.com", "glitch.me", "netlify.app", "herokuapp.com", "repl.co", "000webhostapp.com",
              "sites.google.com", "godaddysites.com", "square.site", "weeblysite.com", "workers.dev", "vercel.app", "r2.dev")
BRANDS = ("paypal", "amazon", "microsoft", "apple", "netflix", "google", "facebook", "instagram", "whatsapp",
          "dhl", "fedex", "chase", "wellsfargo", "citibank", "dropbox", "adobe", "outlook", "office365", "linkedin", "steam")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

FEATURE_NAMES = [
    "url_length", "num_dots", "has_at", "is_https", "num_suspicious_keywords",
    "num_hyphens", "num_digits", "digit_ratio", "has_ip_host", "num_subdomains",
    "host_length", "path_length", "num_query_params", "has_punycode", "is_shortener",
    "risky_tld", "host_entropy", "double_slash_in_path", "has_port",
    "path_depth", "num_special_chars", "free_hosting", "brand_mismatch", "longest_digit_run", "has_script_ext",
]

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())

def normalize(url: str) -> str:
    url = url.strip()
    return url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url

def canonical(url: str) -> str:
    """Strip whitespace and a lone trailing slash after the host, so 'a.com' and 'a.com/' are identical."""
    u = url.strip()
    try:
        p = urlparse(normalize(u))
    except ValueError:
        return u
    return u[:-1] if u.endswith("/") and p.path == "/" and not p.query and not p.fragment else u

def _parse(url: str):
    try:
        p = urlparse(normalize(url))
        p.port  # may raise ValueError on malformed ports
        return p, True
    except ValueError:
        try:
            return urlparse("http://invalid.invalid"), False
        except ValueError:
            raise

def extract_features(url: str) -> dict[str, float]:
    raw = canonical(url)
    try:
        p = urlparse(normalize(raw)); port_ok = True
        _ = p.port
    except ValueError:
        p = urlparse(normalize(raw).split("//", 1)[0] + "//" + "invalid.invalid"); port_ok = False
    host = (p.hostname or "").lower()
    labels = [l for l in host.split(".") if l]
    low = raw.lower()
    digits = sum(c.isdigit() for c in raw)
    return {
        "url_length": len(raw),
        "num_dots": raw.count("."),
        "has_at": int("@" in raw),
        "is_https": int(p.scheme == "https"),
        "num_suspicious_keywords": sum(k in low for k in SUSPICIOUS_KEYWORDS),
        "num_hyphens": host.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / max(len(raw), 1),
        "has_ip_host": int(bool(_IP_RE.match(host))),
        "num_subdomains": max(len(labels) - 2, 0),
        "host_length": len(host),
        "path_length": len(p.path) if p.path != "/" else 0,
        "num_query_params": len([q for q in p.query.split("&") if q]),
        "has_punycode": int("xn--" in host),
        "is_shortener": int(host in SHORTENERS),
        "risky_tld": int(bool(labels) and labels[-1] in RISKY_TLDS),
        "host_entropy": round(_entropy(host), 4),
        "double_slash_in_path": int("//" in p.path),
        "has_port": int(port_ok and p.port is not None),
        "path_depth": len([s for s in p.path.split("/") if s]),
        "num_special_chars": sum(raw.count(c) for c in "%=&_~#"),
        "free_hosting": int(host.endswith(FREE_HOSTS)),
        "brand_mismatch": int(any(b in low.split("?")[0] for b in BRANDS) and not any(".".join(labels[-2:]).startswith(b + ".") for b in BRANDS)),
        "longest_digit_run": max((len(m) for m in re.findall(r"\d+", raw)), default=0),
        "has_script_ext": int(bool(re.search(r"\.(php|asp|aspx|jsp|cgi)(\?|$)", p.path.lower()))),
    }

def explain(feats: dict[str, float]) -> list[str]:
    """Human-readable warning signs (rule-of-thumb signals, not model internals)."""
    r = []
    if feats["has_at"]: r.append("Contains '@' (can hide the real destination)")
    if not feats["is_https"]: r.append("Does not use HTTPS")
    if feats["has_ip_host"]: r.append("Uses a raw IP address instead of a domain")
    if feats["num_suspicious_keywords"]: r.append(f"{int(feats['num_suspicious_keywords'])} suspicious keyword(s) such as login or verify")
    if feats["num_subdomains"] >= 3: r.append("Unusually many subdomains")
    if feats["url_length"] > 75: r.append("Very long URL")
    if feats["num_hyphens"] >= 2: r.append("Multiple hyphens in the domain")
    if feats["has_punycode"]: r.append("Punycode domain (possible lookalike characters)")
    if feats["is_shortener"]: r.append("Link shortener hides the destination")
    if feats["free_hosting"]: r.append("Hosted on a free website-hosting service")
    if feats["brand_mismatch"]: r.append("Mentions a well-known brand but is not on that brand's domain")
    if feats["risky_tld"]: r.append("Top-level domain commonly abused for phishing")
    return r
