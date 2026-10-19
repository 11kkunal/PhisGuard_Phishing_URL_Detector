"""Loading the Dataset"""
from __future__ import annotations
import os, random
import pandas as pd

_BRANDS = ["paypal", "amazon", "microsoft", "apple", "netflix", "chase", "dropbox", "google", "facebook", "dhl"]
_WORDS = ["garden", "travel", "coffee", "photo", "news", "market", "studio", "learn", "health", "design",
          "music", "books", "tech", "sports", "recipes", "forum", "cloud", "shop", "city", "labs"]
_TLD_OK = ["com", "org", "net", "edu", "io", "co.uk", "in"]
_TLD_BAD = ["xyz", "top", "tk", "ml", "click", "com", "net", "icu"]
_KW = ["login", "verify", "secure", "account", "update", "confirm", "signin", "billing", "password"]

def _benign(r: random.Random) -> str:
    host = f"{r.choice(['www.', '', 'blog.', 'docs.'])}{r.choice(_WORDS)}{r.choice(_WORDS)}.{r.choice(_TLD_OK)}"
    path = "/" + "/".join(r.choice(_WORDS) for _ in range(r.randint(0, 3)))
    if r.random() < 0.08: path += "/" + r.choice(["login", "account", "support"])  # legit pages use keywords too
    if r.random() < 0.3: path += f"?id={r.randint(1, 9999)}"
    return f"{'https' if r.random() < 0.85 else 'http'}://{host}{path}"

def _phish(r: random.Random) -> str:
    if r.random() < 0.2:  # label noise: clean-looking phish
        return f"{r.choice(['https', 'http'])}://{r.choice(_WORDS)}{r.choice(_WORDS)}.{r.choice(_TLD_OK)}/{r.choice(_WORDS)}"
    if r.random() < 0.15:
        host = ".".join(str(r.randint(1, 254)) for _ in range(4))
    else:
        sub = ".".join(r.choice(_WORDS) for _ in range(r.randint(0, 3)))
        host = f"{sub + '.' if sub else ''}{r.choice(_BRANDS)}-{r.choice(_KW)}{r.choice(['', '-' + r.choice(_WORDS)])}.{r.choice(_TLD_BAD)}"
    path = "/" + "/".join(r.choice(_KW + _WORDS) for _ in range(r.randint(1, 3))) + f"?session={r.randint(10**5, 10**9)}"
    url = f"{'https' if r.random() < 0.4 else 'http'}://{host}{path}"
    if r.random() < 0.1: url = f"http://{r.choice(_BRANDS)}.com@{host}{path}"
    return url

def make_synthetic(n: int = 6000, seed: int = 42) -> pd.DataFrame:
    r = random.Random(seed)
    rows = [(_benign(r), 0) for _ in range(n // 2)] + [(_phish(r), 1) for _ in range(n // 2)]
    r.shuffle(rows)
    return pd.DataFrame(rows, columns=["url", "label"])

def load(path: str | None) -> tuple[pd.DataFrame, str]:
    if path:
        df = pd.read_csv(path)
        df.columns = [c.strip().lower() for c in df.columns]
        df = df[["url", "label"]].dropna().drop_duplicates("url")
        df["label"] = df["label"].replace({"bad": 1, "good": 0, "phishing": 1, "benign": 0}).astype(int)
        return df.reset_index(drop=True), f"real:{os.path.basename(path)}"
    return make_synthetic(), "synthetic-demo"
