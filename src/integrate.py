"""Step 2 (workshop focus, Topic 5): data integration.

Merges every source into one table with a common schema and handles:
  - schema differences between sources (txt lists, CSV with/without headers, domain-only lists)
  - malformed URLs (dropped, with the reason counted)
  - tuple duplication (the same URL listed twice, within or across sources)
  - entity identification (the same URL written differently: http vs https,
    'www.', letter case in the host, trailing '/', default port, #fragment)
  - value conflicts (one URL labelled phishing by one source and legitimate by another)
  - train/test separation (live test URLs already seen in training are removed)

Output: data/processed/integrated.csv and reports/integration_report.md
"""
import hashlib
import zipfile
from collections import Counter

import numpy as np
import pandas as pd

import re
from urllib.parse import urlsplit

from .config import (LEGIT_TEST_FRACTION, LEGIT_VAL_FRACTION, LIVE, MANUAL,
                     PHISHING_DATABASE_SAMPLE, PROCESSED, RAW, REPORTS, SEED,
                     TRANCO_TRAIN_CANDIDATES)
from .urlutils import clean_url, normalize_key, registered_domain, site_key

# When one URL appears in several sources, the raw form kept is the one from the
# earliest source in this list. Phishing sources come first.
SOURCE_PRIORITY = ["phishing_database", "url_phish", "iscx", "phishtank",
                   "openphish", "phishunt", "kaggle_benign", "commoncrawl", "tranco"]
# Legitimate sources that are split by domain into training and a held-back test pool
HOLDOUT_SOURCES = {"tranco", "kaggle_benign", "commoncrawl"}

# A legitimate-labelled URL is flagged as a suspect label when it matches a typical phishing
# pattern, or its domain also hosts reported phishing, and it is not on a popular domain.
SUSPECT_PATTERN = re.compile(
    r"webscr|cmd=_|sign-?in|log-?in|logon|verif|account|update|secure|banking|password|"
    r"wp-(?:includes|content|admin)/.*\.php|\.php\?.{40,}")
POPULAR_RANK = 100_000
TEST_SOURCES = {"openphish", "phishunt", "phishtank"}


def _frame(urls, label, source, seen=""):
    return pd.DataFrame({"url_raw": list(urls), "label": label, "source": source, "seen": seen})


def _hash01(text: str) -> float:
    """Deterministic pseudo-random number in [0, 1) from a string."""
    return int(hashlib.md5(text.encode()).hexdigest()[:8], 16) / 0x100000000


def _read_lines(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def load_sources(rng) -> pd.DataFrame:
    frames = []

    # Tranco: "rank,domain", no header, domains only -> build a URL
    t = pd.read_csv(RAW / "tranco_top1m.csv.zip", header=None, names=["rank", "domain"])
    frames.append(_frame("https://" + t["domain"].astype(str) + "/", 0, "tranco"))

    # Phishing.Database: one URL per line
    lines = _read_lines(RAW / "phishing_database_active.txt")
    if len(lines) > PHISHING_DATABASE_SAMPLE:
        idx = rng.choice(len(lines), PHISHING_DATABASE_SAMPLE, replace=False)
        lines = [lines[i] for i in idx]
    frames.append(_frame(lines, 1, "phishing_database"))

    # URL-Phish: CSV with 'url' and 'label' (1 = phishing) plus its own features, which we ignore
    up = pd.read_csv(RAW / "url_phish.csv", usecols=["url", "label"])
    frames.append(pd.DataFrame({"url_raw": up["url"], "label": up["label"].astype(int),
                                "source": "url_phish"}))

    # Kaggle Malicious URLs dataset: 'url','type'. Only the benign rows are used. Its phishing
    # rows are older and known to be noisy, and we already have fresher phishing sources.
    kaggle = RAW / "malicious_urls.zip"
    if kaggle.exists():
        with zipfile.ZipFile(kaggle) as z:
            km = pd.read_csv(z.open("malicious_phish.csv"), dtype=str, keep_default_na=False)
        frames.append(_frame(km.loc[km["type"] == "benign", "url"], 0, "kaggle_benign"))

    # ISCX-URL2016 (manual download): headerless one-column CSVs
    for path in MANUAL.rglob("*.csv"):
        name = path.name.lower()
        if "phishing" in name:
            label = 1
        elif "benign" in name:
            label = 0
        else:
            continue  # spam / malware / defacement lists are not part of this task
        df = pd.read_csv(path, header=None, usecols=[0], names=["url"], encoding_errors="replace",
                         dtype=str, keep_default_na=False)
        # ISCX also ships feature tables (Phishing.csv, All.csv, ...) whose first column is a
        # number such as Querylength, not a URL. Only use files that really list URLs.
        sample = df["url"].head(200)
        looks_like_url = sample.str.contains(r"[A-Za-z].*\.[A-Za-z]", regex=True).mean()
        if looks_like_url < 0.8:
            print(f"  skipping {path.name}: it holds precomputed features, not raw URLs")
            continue
        frames.append(_frame(df["url"], label, "iscx"))

    # PhishTank: CSV with a 'url' column, downloaded with an app key or dropped in manually
    for path in list(LIVE.glob("phishtank_*.csv")) + list(MANUAL.glob("*online-valid*.csv")):
        df = pd.read_csv(path, usecols=["url"], encoding_errors="replace")
        frames.append(_frame(df["url"], 1, "phishtank"))

    # Common Crawl sample: current pages; filtered to Tranco domains later
    cc = RAW / "commoncrawl_urls.txt"
    if cc.exists():
        frames.append(_frame(_read_lines(cc), 0, "commoncrawl"))

    # Live text feeds: every snapshot collected so far, tagged with the snapshot date
    for src in ("openphish", "phishunt"):
        for path in sorted(LIVE.glob(f"{src}_*.txt")):
            d = path.stem.split("_")[1]
            frames.append(_frame(_read_lines(path), 1, src, seen=f"{d[:4]}-{d[4:6]}-{d[6:]}"))

    return pd.concat(frames, ignore_index=True)


def md_table(df: pd.DataFrame) -> str:
    cols = [str(c) for c in df.columns]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for row in df.itertuples(index=False):
        cells = []
        for v in row:
            if isinstance(v, (int, np.integer)):
                cells.append(f"{v:,}")
            elif isinstance(v, (float, np.floating)):
                cells.append(f"{v:.4f}")
            else:
                cells.append(str(v).replace("|", "\\|"))
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def main():
    rng = np.random.default_rng(SEED)
    report = ["# Data integration report", ""]

    raw = load_sources(rng)
    raw["url_raw"] = raw["url_raw"].astype(str)
    raw_counts = raw.groupby("source").size().rename("raw_rows")
    print(f"Loaded {len(raw):,} rows from {raw['source'].nunique()} sources")

    # --- Malformed URLs -------------------------------------------------------
    cleaned = raw["url_raw"].map(clean_url)
    raw["url"] = [c[0] for c in cleaned]
    raw["malformed_reason"] = [c[1] for c in cleaned]
    bad = raw[raw["url"].isna()]
    malformed = bad.groupby(["source", "malformed_reason"]).size().unstack(fill_value=0)
    df = raw[raw["url"].notna()].drop(columns=["malformed_reason"]).copy()

    # --- Tuple duplication within a source ----------------------------------
    before = df.groupby("source").size()
    df = df.drop_duplicates(subset=["source", "url"])
    exact_dups = (before - df.groupby("source").size()).rename("exact_duplicates_in_source")

    # --- Entity identification ----------------------------------------------
    df["key"] = df["url"].map(normalize_key)
    variants = df.groupby("key")["url"].nunique()
    multi = variants[variants > 1]
    n_entity_merged = len(multi)
    examples = (df[df["key"].isin(multi.index[:4])]
                .sort_values("key")[["key", "url", "source"]])
    before = df.groupby("source").size()
    df = df.drop_duplicates(subset=["source", "key"])
    entity_dups = (before - df.groupby("source").size()).rename("same_entity_in_source")

    # --- Cross-source duplication and value conflicts ------------------------
    df["prio"] = df["source"].map({s: i for i, s in enumerate(SOURCE_PRIORITY)})
    df = df.sort_values(["key", "prio"])
    df["is_test_src"] = df["source"].isin(TEST_SOURCES)
    df["seen"] = df["seen"].replace("", "9999")
    g = df.groupby("key", sort=False)
    merged = pd.DataFrame({
        "url": g["url"].first(),
        "label_min": g["label"].min(),
        "label_max": g["label"].max(),
        "n_sources": g["source"].nunique(),
        "only_test_sources": g["is_test_src"].all(),
        "seen": g["seen"].min().replace("9999", ""),  # first snapshot the URL appeared in
    })
    multi_src = merged.index[merged["n_sources"] > 1]
    src_lists = (df[df["key"].isin(multi_src)].groupby("key")["source"]
                 .agg(lambda s: "|".join(sorted(set(s)))))
    single_src = g["source"].first()
    merged["sources"] = single_src
    merged.loc[src_lists.index, "sources"] = src_lists
    merged = merged.reset_index()

    conflicts = merged[merged["label_min"] != merged["label_max"]]
    conflict_pairs = Counter(conflicts["sources"]).most_common(10)
    # Rule: a phishing report wins. Popularity lists (Tranco) and benign lists include
    # hosting platforms whose user pages are often abused, so a verified phishing
    # report is the more specific evidence.
    merged["label"] = merged["label_max"]
    conflicts[["key", "url", "sources"]].to_csv(PROCESSED / "label_conflicts.csv", index=False)

    # --- Roles: training pool, live phishing test, held-back Tranco legit test --
    # A live-feed URL that also appears in any training source counts as seen in
    # training, so it stays in training and is not used for testing.
    merged["role"] = np.where(merged["only_test_sources"], "test", "train")
    n_test_overlap = int(((merged["n_sources"] > 1) & ~merged["only_test_sources"]
                          & merged["sources"].str.contains("openphish|phishunt|phishtank")).sum())

    merged["reg_domain"] = merged["url"].map(registered_domain)

    # --- Popularity: Tranco rank of each registered domain ---------------------
    t = pd.read_csv(RAW / "tranco_top1m.csv.zip", header=None, names=["rank", "domain"])
    t["reg"] = ("https://" + t["domain"].astype(str) + "/").map(registered_domain)
    rank = t.groupby("reg")["rank"].min()
    merged["tranco_rank"] = merged["reg_domain"].map(rank).fillna(0).astype(int)

    # Common Crawl covers the whole web, including spam and abandoned sites. Keep only pages
    # on domains in the Tranco top 1M, which are very likely legitimate.
    cc_only = merged["sources"] == "commoncrawl"
    cc_drop = cc_only & (merged["tranco_rank"] == 0)
    cc_dropped, cc_kept = int(cc_drop.sum()), int((cc_only & ~cc_drop).sum())
    merged = merged[~cc_drop]

    # --- Suspect legitimate labels (used by the label-cleaning experiment) ----
    phish_domains = set(merged.loc[merged["label"] == 1, "reg_domain"])
    popular = merged["tranco_rank"].between(1, POPULAR_RANK)
    legit = merged["label"] == 0
    by_domain = legit & merged["reg_domain"].isin(phish_domains) & ~popular
    by_pattern = legit & merged["url"].str.lower().str.contains(SUSPECT_PATTERN) & ~popular
    merged["suspect_reason"] = ""
    merged.loc[by_pattern, "suspect_reason"] = "phishing_pattern"
    merged.loc[by_domain, "suspect_reason"] = "domain_hosts_phishing"
    suspects = (merged[merged["suspect_reason"] != ""].groupby(["suspect_reason", "sources"])
                .size().reset_index(name="urls").sort_values("urls", ascending=False).head(12))

    # --- Hold back legitimate domains for validation and testing --------------
    # Split by registered domain, so no domain has URLs on both sides (all youtube.com URLs
    # go to the same side). Held-back domains are split again into a validation pool (used
    # only to choose the decision threshold) and the final test pool.
    legit_only = merged["sources"].str.split("|").map(lambda x: set(x) <= HOLDOUT_SOURCES)
    u1 = merged["reg_domain"].map(lambda d: _hash01(f"{SEED}:{d}"))
    u2 = merged["reg_domain"].map(lambda d: _hash01(f"val{SEED}:{d}"))
    held = legit_only & (u1 < LEGIT_TEST_FRACTION)
    merged.loc[held & (u2 < LEGIT_VAL_FRACTION), "role"] = "val_legit_pool"
    merged.loc[held & (u2 >= LEGIT_VAL_FRACTION), "role"] = "test_legit_pool"
    # Any other legitimate training URL on a held-back domain would leak that domain
    held_domains = set(merged.loc[held, "reg_domain"])
    leak = (merged["role"] == "train") & merged["reg_domain"].isin(held_domains) & (merged["label"] == 0)
    merged = merged[~leak]

    # --- Training candidates --------------------------------------------------
    # All phishing, and all legitimate URLs except Tranco homepages, which are sampled to keep
    # the file small. pool_weight restores Tranco's true share when an experiment samples
    # "as the sources come".
    train = merged[merged["role"] == "train"].copy()
    tranco_only = (train["sources"] == "tranco") & (train["label"] == 0)
    n_tranco = int(tranco_only.sum())
    keep_tranco = train[tranco_only].sample(min(TRANCO_TRAIN_CANDIDATES, n_tranco), random_state=SEED)
    train = pd.concat([train[~tranco_only], keep_tranco])
    train["pool_weight"] = np.where(train["sources"] == "tranco", n_tranco / max(len(keep_tranco), 1), 1.0)

    test_phish = merged[(merged["role"] == "test") & (merged["label"] == 1)]
    pools = []
    for role, size in (("test_legit_pool", int(len(test_phish) * 100 * 1.5)), ("val_legit_pool", 120_000)):
        p = merged[merged["role"] == role]
        pools.append(p.sample(min(size, len(p)), random_state=SEED))
    final = pd.concat([train, test_phish] + pools, ignore_index=True)
    final["pool_weight"] = final["pool_weight"].fillna(1.0)

    # Held-back URLs must not share a registered domain with any training URL
    train_domains = set(final.loc[final["role"] == "train", "reg_domain"])
    pool_overlap = final["role"].str.endswith("legit_pool") & final["reg_domain"].isin(train_domains)
    final = final[~pool_overlap]
    tp = final["role"] == "test"
    test_domain_overlap = int(final.loc[tp, "reg_domain"].isin(train_domains).sum())

    final["site"] = final["url"].map(lambda u: site_key((urlsplit(u).hostname or "").rstrip(".")))
    final = final[["url", "key", "reg_domain", "site", "label", "role", "sources", "n_sources",
                   "seen", "tranco_rank", "suspect_reason", "pool_weight"]]
    final.to_csv(PROCESSED / "integrated.csv", index=False)

    # --- Report ---------------------------------------------------------------
    per_source = pd.concat([raw_counts,
                            bad.groupby("source").size().rename("malformed"),
                            exact_dups, entity_dups], axis=1).fillna(0).astype(int)
    overlap_counts = (merged.loc[merged["n_sources"] > 1, "sources"].value_counts().head(10)
                      .rename_axis("sources").reset_index(name="urls"))
    report += [
        "## 1. Rows per source", "",
        md_table(per_source.rename_axis("source").reset_index()), "",
        "## 2. Malformed URLs by reason", "",
        md_table(malformed.reset_index()) if len(malformed) else "None.", "",
        "## 3. Entity identification", "",
        f"{n_entity_merged:,} URLs were written in more than one way and were merged into one "
        "entity after normalisation (scheme dropped, host lower-cased, 'www.' removed, default "
        "port, fragment and trailing '/' removed).", "",
        "Examples:", "", md_table(examples), "",
        "## 4. Tuple duplication across sources", "",
        f"{int((merged['n_sources'] > 1).sum()):,} distinct URLs appear in two or more sources.", "",
        md_table(overlap_counts) if len(overlap_counts) else "", "",
        "## 5. Value conflicts (label disagreements)", "",
        f"{len(conflicts):,} URLs are labelled phishing by one source and legitimate by another. "
        "Resolution rule: the phishing label wins. All conflicts are listed in "
        "data/processed/label_conflicts.csv.", "",
        md_table(pd.DataFrame(conflict_pairs, columns=["sources", "urls"])) if conflict_pairs else "", "",
        "## 6. Train / test separation", "",
        f"- Live-feed URLs removed from the test set because they already appear in a training source: {n_test_overlap:,}",
        f"- Held-back legitimate URLs removed because their domain appears in training: {int(pool_overlap.sum()):,}",
        f"- Live phishing test URLs whose registered domain also appears in training (kept, e.g. shared hosting): {test_domain_overlap:,}", "",
        f"- Legitimate URLs dropped from training because their domain was held back for testing: {int(leak.sum()):,}", "",
        "Held-back legitimate URLs by source. The validation pool is only used to choose the "
        "decision threshold; the test pool is the final test.", "",
        md_table(final[final["role"].str.endswith("legit_pool")].groupby(["role", "sources"]).size()
                 .reset_index(name="urls")), "",
        "Live phishing test URLs by the snapshot they first appeared in:", "",
        md_table(final[final["role"] == "test"].groupby("seen").size().reset_index(name="urls")), "",
        "## 7. Common Crawl filtering", "",
        f"{cc_kept:,} Common Crawl URLs were kept and {cc_dropped:,} dropped because their domain "
        "is not in the Tranco top 1M. The kept URLs are current pages on established sites, used "
        "as legitimate deep links.", "",
        "## 8. Suspect legitimate labels", "",
        "Legitimate-labelled URLs on domains outside the Tranco top 100k are flagged when they "
        "match a typical phishing pattern (login, verify, webscr, WordPress PHP files and similar) "
        "or when their domain also hosts reported phishing. The label-cleaning experiment drops them.", "",
        md_table(suspects) if len(suspects) else "None.", "",
        "## 9. Final dataset", "",
        md_table(final.groupby(["role", "label"]).size().reset_index(name="rows")), ""]
    (REPORTS / "integration_report.md").write_text("\n".join(report), encoding="utf-8")
    print(final.groupby(["role", "label"]).size())
    print("Wrote data/processed/integrated.csv and reports/integration_report.md")


if __name__ == "__main__":
    main()
