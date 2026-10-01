"""Step 1: collect URLs.

Training sources (downloaded once):
  - Tranco top 1M (legitimate)
  - Phishing.Database ACTIVE links (phishing)
  - URL-Phish, Mendeley Data 10.17632/65z9twcx3r (phishing + benign)
  - Kaggle Malicious URLs dataset (benign URLs only, which include ISCX-URL2016's benign list)
  - ISCX-URL2016 raw URL lists (optional, manual, see README)

Live test feeds (a new timestamped snapshot every run, so running this daily
grows the test set):
  - OpenPhish community feed
  - Phishunt.io feed
  - PhishTank online-valid (only if PHISHTANK_APP_KEY is set, or a CSV is in data/raw/manual)
"""
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import requests

from .config import LIVE, RAW

UA = {"User-Agent": "Mozilla/5.0 (research script)"}

STATIC = {
    "tranco_top1m.csv.zip": "https://tranco-list.eu/top-1m.csv.zip",
    "phishing_database_active.txt":
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "url_phish.csv":
        "https://data.mendeley.com/public-files/datasets/65z9twcx3r/files/"
        "0e9c55e4-9adb-43f5-8403-1bbd143ebdb6/file_downloaded",
    # Kaggle "Malicious URLs dataset" (sid321axn). Its benign URLs come from ISCX-URL2016
    # and are full URLs with paths, unlike the homepage-only Tranco list.
    "malicious_urls.zip":
        "https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset",
}

LIVE_FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "phishunt": "https://phishunt.io/feed.txt",
}


def download(url: str, dest, timeout=300) -> bool:
    try:
        with requests.get(url, headers=UA, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            tmp = dest.with_suffix(dest.suffix + ".part")
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
            tmp.replace(dest)
        print(f"  saved {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return True
    except requests.RequestException as e:
        # Some hosts (e.g. Mendeley) block Python's HTTP client but accept curl
        if shutil.which("curl"):
            r = subprocess.run(["curl", "-sSLf", "--max-time", str(timeout), "-o", str(dest), url])
            if r.returncode == 0 and dest.exists() and dest.stat().st_size > 0:
                print(f"  saved {dest.name} via curl ({dest.stat().st_size / 1e6:.1f} MB)")
                return True
        print(f"  FAILED {url}: {e}", file=sys.stderr)
        return False


def main(refresh_static: bool = False):
    print("Static training sources")
    for name, url in STATIC.items():
        dest = RAW / name
        if dest.exists() and not refresh_static:
            print(f"  {name} already present, skipping")
            continue
        download(url, dest)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    print(f"Live test feeds (snapshot {stamp})")
    feeds = dict(LIVE_FEEDS)
    key = os.environ.get("PHISHTANK_APP_KEY")
    if key:
        feeds["phishtank"] = f"http://data.phishtank.com/data/{key}/online-valid.csv"
    else:
        print("  PhishTank skipped: set PHISHTANK_APP_KEY, or drop online-valid.csv into data/raw/manual/")
    for name, url in feeds.items():
        ext = ".csv" if name == "phishtank" else ".txt"
        download(url, LIVE / f"{name}_{stamp}{ext}", timeout=120)


if __name__ == "__main__":
    main(refresh_static="--refresh" in sys.argv)
