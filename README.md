# Phishing URL Detection (Group 09, CSC1104)

Classifies URLs as phishing or legitimate from the URL string alone, using a decision tree.
The page is never loaded.

## Quick start

```bash
pip install -r requirements.txt
python run_all.py                 # download data, integrate, extract features, analyse, train, evaluate
python run_all.py --no-collect    # rerun without downloading again
python -m src.predict "http://secure-paypal.account-verify.xyz/login/webscr.php"
```

The full run takes about 25 minutes, mostly tuning the tree. `src.predict` prints the verdict and the tree rules that led to it.

## Pipeline

| Step | File | What it does |
|---|---|---|
| 1. Collect | `src/collect.py` | Downloads Tranco, Phishing.Database, URL-Phish and the Kaggle Malicious URLs dataset once. Saves a timestamped snapshot of the OpenPhish and Phishunt live feeds on every run. |
| 2. Integrate | `src/integrate.py` | Merges all sources. Handles malformed URLs, tuple duplication, entity identification, label conflicts and train/test separation. Writes `reports/integration_report.md`. |
| 3. Features | `src/features.py` | 22 features per URL: lengths, dots, hyphens, `@`, IP host, subdomains, entropy, digits, special characters, suspicious words, URL shortener and more. Computed on the normalised URL, see below. |
| 4. Analysis | `src/analysis.py` | Class distributions, Gini and information gain of each feature, correlation and redundancy. Writes `reports/analysis_report.md`. |
| 5. Train and evaluate | `src/train_eval.py` | Domain-grouped split, grouped 5-fold tuning of the tree, evaluation at 1:1, 1:10, 1:50 and 1:100. Writes `reports/results_report.md`. |

Settings such as sample sizes, ratios and the random seed are in `src/config.py`.

## Data sources

| Source | Label | Used for | How it is obtained |
|---|---|---|---|
| Tranco top 1M | legitimate | training, and held-back domains for testing | automatic |
| Phishing.Database (ACTIVE links) | phishing | training, 50,000 sampled | automatic |
| URL-Phish (Mendeley, doi 10.17632/65z9twcx3r) | both | training | automatic |
| Kaggle Malicious URLs dataset (sid321axn) | legitimate rows only | training, and held-back domains for testing | automatic |
| ISCX-URL2016 raw URL lists | both | training | optional, **manual**, see below |
| OpenPhish | phishing | live test | automatic, snapshot per run |
| Phishunt.io | phishing | live test | automatic, snapshot per run |
| PhishTank | phishing | live test | **needs an API key**, see below |

**Kaggle Malicious URLs dataset.** Its legitimate URLs come from ISCX-URL2016 and are full URLs with paths, which Tranco lacks. Its phishing rows are not used because they are older and known to be noisy.

**ISCX-URL2016** is optional now that the Kaggle dataset covers its benign URLs. It sits behind a registration form at https://www.unb.ca/cic/datasets/url-2016.html.
We need the raw URL lists, such as `phishing_dataset.csv` and `Benign_list_big_final.csv`, not the feature tables (`All.csv`, `Phishing.csv`, `*_Infogain.csv`), which contain no URLs.
Put the URL lists anywhere under `data/raw/manual/`. The loader uses CSVs whose name contains `phishing` or `benign` and skips any file whose first column is not URLs.

**PhishTank** needs an application key. Set `PHISHTANK_APP_KEY` before running, or save `online-valid.csv` into `data/raw/manual/`.

**Growing the live test set:** each run of `python -m src.collect` saves a new snapshot of the live feeds. Running it once a day for a week or two gives a much larger test set than one snapshot.

## Results (24 Sep 2026)

Training used 132,184 balanced URLs. The live test used 1,030 phishing URLs that never appeared in training.
Legitimate test URLs come from domains held back from training: about 70% Tranco homepages and 30% Kaggle deep links.

Held-out domains, balanced:

| precision | recall | F1 | average precision |
|---|---|---|---|
| 0.875 | 0.850 | 0.863 | 0.932 |

Live phishing URLs at realistic imbalance, mean of 10 draws:

| legit:phishing | precision | recall | F1 | false positives |
|---|---|---|---|---|
| 1:1 | 0.846 | 0.803 | 0.824 | 150 |
| 1:10 | 0.356 | 0.797 | 0.492 | 1,485 |
| 1:50 | 0.102 | 0.804 | 0.180 | 7,328 |
| 1:100 | 0.054 | 0.804 | 0.101 | 14,593 |

At 1:100, accuracy is 0.858 while precision is only 0.054. This is why the project reports precision and recall instead of accuracy.

The first version, trained without deep-link legitimate URLs, reached 0.60 precision at 1:100. That score was inflated: the tree had learned that any URL with a path is phishing.

## Known issues to discuss in the report

- **Normalised features.** The sources disagree on scheme and "www.": Tranco lists bare domains, most Kaggle URLs have no scheme, and phishing feeds usually include one. Features are therefore computed on the normalised URL, and there is no HTTPS feature. Otherwise the tree would learn which source a URL came from.
- **Unseen popular domains.** The split is by domain, so some big sites never appear in training. The tree flags 99% of held-back YouTube video links, because random video IDs look like phishing.
- **Label noise.** Some Kaggle "benign" URLs are clearly phishing, such as a `webscrprim.php` page. Some reported false positives are really the model being right.
- **Age of the data.** The Kaggle legitimate URLs are from around 2016 to 2019, while the live phishing URLs are from today.
- **Small live test.** 1,030 phishing URLs from one day, mostly on hosting platforms. Collect daily to grow it.
- **Fixed 0.5 threshold.** At 1:100 a higher threshold trades recall for precision. The PR curves show that trade-off.
- **Large tree.** The tuned tree has 613 leaves, so only the top levels are readable. The top-levels figure and `src.predict` keep it explainable.

## Output files

- `reports/integration_report.md`: integration statistics for the workshop (Topic 5)
- `reports/analysis_report.md`: feature ranking, distributions, redundancy, shortcut check
- `reports/results_report.md`: tuned tree, metrics, PR curves, host-only check
- `reports/tree_rules.txt`: every rule of the tree
- `reports/figures/`: all charts
- `models/decision_tree.joblib`: the trained tree
- `data/processed/label_conflicts.csv`: URLs the sources disagree on
