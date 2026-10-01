"""Classify URLs with the trained tree and print the rule path that led to the decision.

Usage:
    python -m src.predict "http://paypal-login.verify-account.example.xyz/signin.php" https://github.com/
"""
import sys
from urllib.parse import urlsplit

import joblib
import pandas as pd

from .config import ROOT
from .features import extract
from .urlutils import clean_url, on_free_hosting, registered_domain


def explain(model, features, row: pd.DataFrame) -> list[str]:
    tree = model.tree_
    node_ids = model.decision_path(row).indices
    steps = []
    for node in node_ids:
        if tree.children_left[node] == tree.children_right[node]:  # leaf
            break
        f = features[tree.feature[node]]
        thr = tree.threshold[node]
        val = row.iloc[0][f]
        op = "<=" if val <= thr else ">"
        steps.append(f"{f} = {val:g} {op} {thr:.2f}")
    return steps


def main(urls):
    bundle = joblib.load(ROOT / "models" / "decision_tree.joblib")
    model, features = bundle["model"], bundle["features"]
    thr, allow = bundle.get("threshold", 0.5), set(bundle.get("allowlist", []))
    for raw in urls:
        url, reason = clean_url(raw)
        if url is None:
            print(f"{raw}\n  malformed URL ({reason})\n")
            continue
        domain = registered_domain(url)
        host = (urlsplit(url).hostname or "").removeprefix("www.")
        if domain in allow and not on_free_hosting(host):
            print(f"{url}\n  legitimate ({domain} is a top-ranked domain on the allowlist)\n")
            continue
        row = pd.DataFrame([extract(url)])[features]
        p = model.predict_proba(row)[0, 1]
        verdict = "PHISHING" if p >= thr else "legitimate"
        print(f"{url}\n  {verdict} (phishing score {p:.2f}, threshold {thr:.2f})")
        for s in explain(model, features, row):
            print(f"    because {s}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1:])
