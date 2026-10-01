# Phishing URL Detection (Group 09, CSC1104)

Classifies URLs as phishing or legitimate from the URL string alone, using a decision tree.
The page is never loaded.

## Quick start

```bash
pip install -r requirements.txt
python run_all.py                 # download data, integrate, features, analysis, experiments, final model
python run_all.py --no-collect    # rerun without downloading again
python -m src.predict "http://secure-paypal.account-verify.xyz/login/webscr.php"
```

The first run downloads about 300 MB and takes about an hour. A rerun with `--no-collect` takes about 45 minutes, mostly integration and tuning.
`src.predict` prints the verdict and the tree rules that led to it.

## Pipeline

| Step | File | What it does |
|---|---|---|
| 1. Collect | `src/collect.py` | Downloads Tranco, Phishing.Database, URL-Phish, the Kaggle Malicious URLs dataset and a Common Crawl sample once. Saves a dated snapshot of the OpenPhish and Phishunt live feeds on every run. |
| 2. Integrate | `src/integrate.py` | Merges all sources. Handles malformed URLs, duplicates, entity identification, label conflicts, suspect labels and the train / validation / test split by domain. Writes `reports/integration_report.md`. |
| 3. Features | `src/features.py` | 30 features per URL, computed on the normalised URL. |
| 4. Analysis | `src/analysis.py` | Class distributions, Gini and information gain, correlation and redundancy. Starts `reports/analysis_report.md`. |
| 5. Experiments | `src/experiments.py` | Adds each improvement one at a time and scores every step on the same test set. Adds a section to the analysis report. |
| 6. Final model | `src/train_eval.py` | Trains the final tree, evaluates it at 1:1 to 1:100, and adds the error analysis and over-time sections to the analysis report. Writes `reports/results_report.md`. |

Shared training and scoring code is in `src/dataset.py`. Settings such as sample sizes, ratios, the per-site cap and the allowlist size are in `src/config.py`.

## Data sources

| Source | Label | Used for | How it is obtained |
|---|---|---|---|
| Tranco top 1M | legitimate | training, validation and test, split by domain | automatic |
| Phishing.Database (ACTIVE links) | phishing | training, 50,000 sampled | automatic |
| URL-Phish (Mendeley, doi 10.17632/65z9twcx3r) | both | training | automatic |
| Kaggle Malicious URLs dataset (sid321axn) | legitimate rows only | training, validation and test | automatic |
| Common Crawl (CC-MAIN-2026-39 index sample) | legitimate, Tranco domains only | training, validation and test | automatic |
| ISCX-URL2016 raw URL lists | both | training | optional, **manual**, see below |
| OpenPhish | phishing | live test | automatic, snapshot per run |
| Phishunt.io | phishing | live test | automatic, snapshot per run |
| PhishTank | phishing | live test | **needs an API key**, see below |

**Kaggle Malicious URLs dataset.** Its legitimate URLs come from ISCX-URL2016 and are full URLs with paths. Its phishing rows are not used. Many of its "benign" URLs are actually phishing; the integration step flags them as suspect labels.

**Common Crawl.** Random blocks of the crawl's URL index give current pages. Only pages on Tranco top-1M domains are kept.

**ISCX-URL2016** is optional. It sits behind a registration form at https://www.unb.ca/cic/datasets/url-2016.html.
Only the raw URL lists work, such as `phishing_dataset.csv` and `Benign_list_big_final.csv`. The feature tables (`All.csv`, `Phishing.csv`, `*_Infogain.csv`) contain no URLs and are skipped.

**PhishTank** needs an application key. Set `PHISHTANK_APP_KEY` before running, or save `online-valid.csv` into `data/raw/manual/`.

## Daily collection

`scripts/collect_daily.bat` saves a new live-feed snapshot. On this laptop it is scheduled in Windows Task Scheduler as `PhishingURL_DailyCollect`, every day at 12:00. It only runs if the laptop is on at that time.

```bat
schtasks /Query /TN "PhishingURL_DailyCollect"     :: check it
schtasks /Delete /TN "PhishingURL_DailyCollect" /F :: remove it
```

Rerun `python run_all.py --no-collect` after a week or two to use the new snapshots.

## Results (1 Oct 2026)

The live test uses 1,398 phishing URLs from two snapshots a week apart, none seen in training. They are mixed with legitimate URLs from 145,115 held-back domains. Each figure is the mean of 10 draws.

**Improvements, one at a time.** F1 at 1 phishing URL per 100 legitimate:

| Step | Precision | Recall | F1 |
|---|---|---|---|
| Baseline | 0.049 | 0.798 | 0.092 |
| + cap of 20 URLs per site | 0.031 | 0.803 | 0.061 |
| + legitimate path share matched to phishing | 0.063 | 0.792 | 0.117 |
| + Common Crawl deep links | 0.059 | 0.803 | 0.109 |
| + suspect labels removed | 0.057 | 0.792 | 0.106 |
| + 8 new features | 0.070 | 0.843 | 0.129 |
| + cost-complexity pruning | 0.073 | 0.843 | 0.135 |
| + threshold tuned on validation | 0.320 | 0.577 | 0.412 |
| + allowlist of Tranco top 10,000 | 0.394 | 0.575 | 0.468 |
| Random forest, for comparison | 0.599 | 0.553 | 0.575 |

**Final tree at each ratio:**

| Legitimate : phishing | Precision | Recall | F1 | False positives |
|---|---|---|---|---|
| 1:1 | 0.985 | 0.578 | 0.728 | 13 |
| 1:10 | 0.864 | 0.571 | 0.687 | 126 |
| 1:50 | 0.565 | 0.575 | 0.570 | 618 |
| 1:100 | 0.396 | 0.572 | 0.468 | 1,219 |

The final tree has 148 leaves, down from 643. Its threshold is 0.967. The analysis report explains each step, and the main findings are below.

## Findings and known issues

- **The threshold matters most.** At 1:100 the default 0.5 flags far too many legitimate pages. A threshold tuned on validation data roughly tripled F1, at the cost of recall.
- **Steps interact.** The per-site cap alone made things worse, because it removed deep links but kept every homepage, which brought back the "has a path means phishing" shortcut. Matching the path share fixed it.
- **Label noise is large.** Many Kaggle "benign" URLs are phishing. 48% of the final model's false positives are such suspect labels. On a test pool without them, F1 at 1:100 is 0.565 instead of 0.468.
- **Allowlists need care.** The first allowlist trusted weebly.com and godaddysites.com, so it let through phishing hosted on them. Free hosting platforms are now never allowlisted.
- **Strict threshold, missed tricks.** At 0.967, some obvious tricks score just below the cut-off, such as `http://paypal.com@evil-site.ru/login` at 0.92.
- **Missed phishing is mostly bare homepages.** 53% of missed phishing URLs have no path at all. URL text alone cannot judge those; page content or domain age would be needed.
- **Performance drops over time.** Recall is 0.607 on the first snapshot and 0.476 on URLs first seen a week later, with no retraining in between.
- **Interpretability costs accuracy.** A random forest reaches F1 0.575 against 0.468 for the single tree.
- **Normalised features.** Sources disagree on scheme and "www.", so features are computed on the normalised URL and there is no HTTPS feature. Otherwise the tree would learn which source a URL came from.

## Output files

- `reports/integration_report.md`: integration statistics for the workshop (Topic 5)
- `reports/analysis_report.md`: feature analysis, improvement experiments, error analysis, performance over time
- `reports/results_report.md`: final tree, metrics, PR curves, host-only check, results by source
- `reports/experiments.csv`: every number from the experiments
- `reports/error_examples.csv`: 100 false positives and 100 missed phishing URLs
- `reports/tree_rules.txt`: every rule of the final tree
- `reports/figures/`: all charts
- `models/decision_tree.joblib`: the final tree, its threshold and the allowlist
- `data/processed/label_conflicts.csv`: URLs the sources disagree on
