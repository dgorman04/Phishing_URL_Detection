"""Shared paths and settings for the phishing URL pipeline."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
MANUAL = RAW / "manual"          # put ISCX-URL2016 / PhishTank CSVs here by hand
LIVE = RAW / "live"              # timestamped snapshots of live feeds
PROCESSED = ROOT / "data" / "processed"
REPORTS = ROOT / "reports"
FIGURES = REPORTS / "figures"

SEED = 42

# Phishing.Database ACTIVE has ~800k URLs; sample it so the training set stays balanced
PHISHING_DATABASE_SAMPLE = 50_000
# Share of legitimate domains held back (never trained on) for validation and testing
LEGIT_TEST_FRACTION = 0.5
# Of the held-back legitimate domains, this share is used to pick the decision threshold
# (validation) and the rest is the final test pool. Split by domain.
LEGIT_VAL_FRACTION = 0.3
# Tranco homepages kept as legitimate training candidates. All other legitimate sources are
# kept in full; the experiments sample their training sets from these candidates.
TRANCO_TRAIN_CANDIDATES = 150_000

# Common Crawl: random blocks of the URL index, filtered to Tranco domains, give current
# legitimate deep links. Each block holds about 3,000 URLs.
CC_CRAWL = "CC-MAIN-2026-39"
CC_BLOCKS = 200

# Improvement settings
MAX_URLS_PER_SITE = 20       # cap per site in training (each shared-hosting site counts separately)
ALLOWLIST_TOP = 10_000       # registered domains in the Tranco top N are treated as legitimate
TUNE_FOLDS = 3
# Imbalance ratios (legit : phishing) used in the live test
RATIOS = [1, 10, 50, 100]
# Repeats of the random legit sample at each ratio
RATIO_REPEATS = 10

for p in (RAW, MANUAL, LIVE, PROCESSED, REPORTS, FIGURES):
    p.mkdir(parents=True, exist_ok=True)
