"""Build data/urls.csv. """
import io, glob, os, tarfile, urllib.request
from urllib.parse import urlparse
import pandas as pd
from phishguard.features import canonical

PH = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"
CL = "https://codeload.github.com/citizenlab/test-lists/tar.gz/refs/heads/master"
TOP = "https://raw.githubusercontent.com/Kikobeats/top-sites/master/top-sites.json"
get = lambda u: urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "phishguard"}), timeout=120).read()

def ok(u: str) -> bool:
    try:
        p = urlparse(u); p.port
        return p.scheme in ("http", "https") and bool(p.hostname) and len(u) <= 2048
    except ValueError:
        return False

def stratum(u: str) -> int:
    p = urlparse(u); n = len(p.path.strip("/"))
    return (0 if n == 0 else 1 if n <= 8 else 2 if n <= 20 else 3 if n <= 40 else 4) * 2 + int(bool(p.query))

phish = pd.Series(get(PH).decode("utf8", "ignore").split("\n")).str.strip()
phish = pd.DataFrame({"url": phish[phish != ""].drop_duplicates()})
benign = []
with tarfile.open(fileobj=io.BytesIO(get(CL))) as t:
    for m in t.getmembers():
        if m.name.endswith(".csv") and "/lists/" in m.name and "LEGEND" not in m.name:
            try: benign.append(pd.read_csv(t.extractfile(m), on_bad_lines="skip")["url"])
            except Exception: pass
import json
for d in json.loads(get(TOP)):
    benign.append(pd.Series([f"https://{d['rootDomain']}"]))
benign = pd.DataFrame({"url": pd.concat(benign).dropna().astype(str).str.strip().drop_duplicates()})

out = []
for df, lab in ((phish, 1), (benign, 0)):
    df = df.assign(url=df.url.map(canonical)).drop_duplicates("url"); df = df[df.url.map(ok)].copy(); df["label"] = lab; df["s"] = df.url.map(stratum); out.append(df)
ph, be = out
rows = []
for s in sorted(set(ph.s) & set(be.s)):
    n = min((ph.s == s).sum(), (be.s == s).sum())
    rows += [ph[ph.s == s].sample(n, random_state=42), be[be.s == s].sample(n, random_state=42)]
data = pd.concat(rows)[["url", "label"]].sample(frac=1, random_state=42)
os.makedirs("data", exist_ok=True); data.to_csv("data/urls.csv", index=False)
print(data.label.value_counts().to_dict(), "->", "data/urls.csv")
