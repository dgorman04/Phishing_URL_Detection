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
import gzip
import json
import os
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import CC_BLOCKS, CC_CRAWL, LIVE, RAW, SEED

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


def collect_commoncrawl(dest, n_blocks=CC_BLOCKS):
    """Sample current URLs from random blocks of the Common Crawl URL index.

    The index search server is often overloaded, so this reads the raw index files instead.
    cluster.idx (about 100 MB, downloaded once) lists every block of the index. We pick
    random blocks and fetch each with an HTTP range request. Each block is one gzip member
    of about 3,000 index lines. Only HTML pages that returned status 200 are kept.
    """
    base = f"https://data.commoncrawl.org/cc-index/collections/{CC_CRAWL}/indexes/"
    idx = RAW / f"cc_cluster_{CC_CRAWL}.idx"
    if not idx.exists() and not download(base + "cluster.idx", idx, timeout=900):
        return
    with open(idx, encoding="utf-8", errors="replace") as f:
        entries = [ln.rstrip("\n").split("\t") for ln in f]
    rnd = random.Random(SEED)
    blocks = [(e[1], int(e[2]), int(e[3])) for e in rnd.sample(entries, n_blocks)]

    session = requests.Session()
    retry = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    urls = []
    for i, (fname, offset, length) in enumerate(sorted(blocks), 1):
        try:
            r = session.get(base + fname, headers={**UA, "Range": f"bytes={offset}-{offset + length - 1}"},
                            timeout=120)
            r.raise_for_status()
            for line in gzip.decompress(r.content).decode("utf-8", "replace").splitlines():
                rec = json.loads(line.split(" ", 2)[2])
                if (rec.get("status") == "200" and rec.get("mime") == "text/html"
                        and not rec["url"].endswith("robots.txt")):
                    urls.append(rec["url"])
        except (requests.RequestException, OSError, ValueError, IndexError) as e:
            print(f"  block {fname}@{offset} failed: {e}", file=sys.stderr)
        time.sleep(0.5)  # be polite to the Common Crawl servers
        if i % 25 == 0:
            print(f"  {i}/{len(blocks)} blocks, {len(urls):,} URLs")
    dest.write_text("\n".join(urls), encoding="utf-8")
    print(f"  saved {dest.name} ({len(urls):,} URLs)")


def main(refresh_static: bool = False):
    print("Static training sources")
    for name, url in STATIC.items():
        dest = RAW / name
        if dest.exists() and not refresh_static:
            print(f"  {name} already present, skipping")
            continue
        download(url, dest)
    cc = RAW / "commoncrawl_urls.txt"
    if cc.exists() and not refresh_static:
        print(f"  {cc.name} already present, skipping")
    else:
        print(f"Common Crawl sample ({CC_CRAWL}, {CC_BLOCKS} index blocks)")
        collect_commoncrawl(cc)

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
