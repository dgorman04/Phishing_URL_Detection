"""Step 3: turn each URL into one row of numeric features.

Only the URL string is used. The page is never fetched.

Features are computed on the normalised form of the URL (no scheme, no leading 'www.',
no trailing '/'). The sources disagree on these details: Tranco lists bare domains, most
Kaggle benign URLs have no scheme, and phishing feeds usually include one. Computing
features on the raw text would let the tree learn which source a URL came from instead
of whether it is phishing. For the same reason there is no HTTPS feature.

Output: data/processed/features.csv
"""
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import pandas as pd

from .config import PROCESSED
from .urlutils import is_ip, normalize_key, split_host

SUSPICIOUS_WORDS = [
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification", "account",
    "update", "secure", "security", "banking", "confirm", "password", "passwd", "webscr",
    "wallet", "billing", "suspend", "unlock", "recover", "authenticate", "validate",
    "invoice", "support", "unusual", "limited", "bonus", "free", "gift", "claim",
    "paypal", "apple", "microsoft", "office365", "outlook", "netflix", "amazon", "ebay",
]

SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "bit.do", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "rebrand.ly", "t.ly", "s.id",
    "v.gd", "qrco.de", "lnkd.in", "trib.al", "soo.gd", "clck.ru", "shorte.st", "x.co",
    "u.to", "tr.im", "bl.ink", "short.io", "urlz.fr", "l.ead.me", "tinyurl.is", "shorturl.gg",
}

# Everything that is not a letter, digit or one of the common separators . / : -
_SPECIAL = re.compile(r"[^A-Za-z0-9./:\-]")

# Features that depend only on the host name. Used for the host-only robustness check.
HOST_FEATURES = ["host_length", "host_hyphens", "host_digits", "host_entropy",
                 "num_subdomains", "ip_host", "is_shortener", "has_punycode", "has_port"]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def extract(url: str) -> dict:
    url = normalize_key(url)  # e.g. "HTTPS://www.Example.com/a/" -> "example.com/a"
    parts = urlsplit("http://" + url)
    host = (parts.hostname or "").rstrip(".")
    no_scheme = url
    sub, _, _ = split_host(host)
    sub_labels = [p for p in sub.split(".") if p] if sub else []
    if sub_labels and sub_labels[0] == "www":
        sub_labels = sub_labels[1:]
    lower = url.lower()
    path = parts.path

    return {
        # overall shape
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path.rstrip("/")),
        "query_length": len(parts.query),
        "path_depth": len([p for p in path.split("/") if p]),
        "num_params": len([p for p in parts.query.split("&") if p]),
        # character counts
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "has_at": int("@" in no_scheme),
        "digit_count": sum(ch.isdigit() for ch in url),
        "digit_ratio": sum(ch.isdigit() for ch in url) / len(url),
        "special_char_count": len(_SPECIAL.findall(no_scheme)),
        "entropy": entropy(no_scheme),
        # host
        "ip_host": int(is_ip(host)),
        "num_subdomains": len(sub_labels),
        "host_hyphens": host.count("-"),
        "host_digits": sum(ch.isdigit() for ch in host),
        "host_entropy": entropy(host),
        "has_punycode": int("xn--" in host),
        "has_port": int(parts.port is not None),
        "is_shortener": int(host in SHORTENERS),
        # content words
        "suspicious_word_count": sum(w in lower for w in SUSPICIOUS_WORDS),
    }


FEATURES = list(extract("https://example.com/").keys())


def main():
    df = pd.read_csv(PROCESSED / "integrated.csv", keep_default_na=False)
    feats = pd.DataFrame([extract(u) for u in df["url"]])
    out = pd.concat([df[["url", "reg_domain", "label", "role", "sources"]], feats], axis=1)
    out.to_csv(PROCESSED / "features.csv", index=False)
    print(f"Wrote {len(out):,} rows x {len(FEATURES)} features to data/processed/features.csv")


if __name__ == "__main__":
    main()
