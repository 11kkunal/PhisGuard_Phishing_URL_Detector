"""Train + compare NB / Decision Tree / k-NN, select best by CV F1, persist model + reports.
Usage: python train.py [--data data/urls.csv]"""
import argparse, json, os, time
from urllib.parse import urlparse
import joblib, pandas as pd
from sklearn.model_selection import GroupShuffleSplit, GroupKFold, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from phishguard import data, features

SEED = 42
BASE = os.path.dirname(os.path.abspath(__file__))
MODELS = {
    "Naive Bayes": Pipeline([("clf", GaussianNB())]),
    "Decision Tree": Pipeline([("clf", DecisionTreeClassifier(max_depth=10, min_samples_leaf=20, class_weight="balanced", random_state=SEED))]),
    "k-NN": Pipeline([("scale", StandardScaler()), ("clf", KNeighborsClassifier(n_neighbors=15, weights="distance"))]),
}

def host(u):
    try: return urlparse(features.normalize(u)).hostname or u
    except ValueError: return u

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--data"); a = ap.parse_args()
    df, source = data.load(a.data)
    X = pd.DataFrame([features.extract_features(u) for u in df.url])[features.FEATURE_NAMES]
    y, g = df.label.astype(int), df.url.map(host)
    tr, te = next(GroupShuffleSplit(1, test_size=0.2, random_state=SEED).split(X, y, g))
    Xtr, Xte, ytr, yte, gtr = X.iloc[tr], X.iloc[te], y.iloc[tr], y.iloc[te], g.iloc[tr]
    results = {}
    for name, m in MODELS.items():
        cv_f1 = cross_val_score(m, Xtr, ytr, cv=GroupKFold(5), groups=gtr, scoring="f1")
        m.fit(Xtr, ytr)
        t = time.perf_counter(); pred = m.predict(Xte); ms = (time.perf_counter() - t) / len(Xte) * 1000
        tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
        results[name] = dict(accuracy=accuracy_score(yte, pred), precision=precision_score(yte, pred),
                             recall=recall_score(yte, pred), f1=f1_score(yte, pred),
                             cv_f1_mean=cv_f1.mean(), cv_f1_std=cv_f1.std(),
                             latency_ms_per_url=ms, tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))
    best = max(results, key=lambda k: results[k]["cv_f1_mean"])
    final = MODELS[best].fit(X, y)
    meta = dict(best_model=best, data_source=source, n_samples=len(df), features=features.FEATURE_NAMES, results=results)
    out = os.path.join(BASE, "models"); os.makedirs(out, exist_ok=True)
    joblib.dump({"model": final, "meta": meta}, os.path.join(out, "phishguard.joblib"))
    json.dump(meta, open(os.path.join(out, "metrics.json"), "w"), indent=2)
    pd.set_option("display.width", 200)
    print(f"Data: {source} ({len(df)} URLs)\n", pd.DataFrame(results).T[["accuracy", "precision", "recall", "f1", "cv_f1_mean", "latency_ms_per_url"]].round(4),
          f"\n\nBest model (by 5-fold grouped CV F1): {best}")
    clf = final.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        print("Top features:", [(n, round(float(v), 3)) for n, v in sorted(zip(features.FEATURE_NAMES, clf.feature_importances_), key=lambda t: -t[1])[:6]])

if __name__ == "__main__":
    main()
