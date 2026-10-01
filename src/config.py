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
# Share of legitimate domains (Tranco, Kaggle benign) held back, never trained on, for the imbalance test
LEGIT_TEST_FRACTION = 0.5
# Imbalance ratios (legit : phishing) used in the live test
RATIOS = [1, 10, 50, 100]
# Repeats of the random legit sample at each ratio
RATIO_REPEATS = 10

for p in (RAW, MANUAL, LIVE, PROCESSED, REPORTS, FIGURES):
    p.mkdir(parents=True, exist_ok=True)
