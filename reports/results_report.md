# Results

Training data: 132,184 URLs (balanced). Held-out domains: 24,787 URLs. Live phishing test URLs: 1,030. Held-back legitimate pool: 152,601.

## Chosen tree

Grouped 5-fold cross-validation picked {'criterion': 'gini', 'max_depth': 25, 'min_samples_leaf': 100} (CV average precision 0.9323). The tree has depth 24 and 613 leaves.

## Held-out domains (balanced, same sources as training)

| precision | recall | f1 | avg_precision | accuracy | tp | fp | fn | tn |
|---|---|---|---|---|---|---|---|---|
| 0.8752 | 0.8502 | 0.8625 | 0.9315 | 0.8695 | 10,148 | 1,447 | 1,788 | 11,404 |

## Live phishing URLs at realistic imbalance

Mean ± standard deviation over 10 draws. Each draw takes a fresh random sample of legitimate URLs and a bootstrap resample of the phishing URLs. Threshold 0.5. Accuracy is shown only for contrast: at 1:100 a model that flags nothing already scores 0.990.

| ratio | precision | recall | f1 | avg_precision | accuracy | false_positives | phishing_caught |
|---|---|---|---|---|---|---|---|
| 1:1 | 0.846 ± 0.010 | 0.803 ± 0.010 | 0.824 ± 0.006 | 0.908 ± 0.006 | 0.828 ± 0.006 | 150 | 827 |
| 1:10 | 0.356 ± 0.008 | 0.797 ± 0.012 | 0.492 ± 0.009 | 0.628 ± 0.011 | 0.850 ± 0.004 | 1,485 | 821 |
| 1:50 | 0.102 ± 0.001 | 0.804 ± 0.013 | 0.180 ± 0.002 | 0.327 ± 0.014 | 0.857 ± 0.001 | 7,328 | 829 |
| 1:100 | 0.054 ± 0.001 | 0.804 ± 0.013 | 0.101 ± 0.002 | 0.214 ± 0.010 | 0.858 ± 0.001 | 14,593 | 828 |

![pr](figures/pr_curves.png)

![importance](figures/feature_importance.png)

![tree](figures/tree_top_levels.png)

## Robustness check: host-only features

Share of legitimate URLs with a path or query: 25.1% in training, 27.4% in the held-back test pool, against 71.1% of training phishing URLs. Where these differ a lot, path features become a shortcut. This model uses only features of the host name: host_length, host_hyphens, host_digits, host_entropy, num_subdomains, ip_host, is_shortener, has_punycode, has_port.

Best parameters {'criterion': 'gini', 'max_depth': 25, 'min_samples_leaf': 100}, depth 21.

| precision | recall | f1 | avg_precision | accuracy | tp | fp | fn | tn |
|---|---|---|---|---|---|---|---|---|
| 0.8278 | 0.6215 | 0.7100 | 0.8329 | 0.7555 | 7,418 | 1,543 | 4,518 | 11,308 |

| ratio | precision | recall | f1 | avg_precision | accuracy | false_positives | phishing_caught |
|---|---|---|---|---|---|---|---|
| 1:1 | 0.861 ± 0.011 | 0.782 ± 0.014 | 0.820 ± 0.011 | 0.893 ± 0.008 | 0.828 ± 0.010 | 130 | 806 |
| 1:10 | 0.386 ± 0.008 | 0.777 ± 0.012 | 0.516 ± 0.008 | 0.572 ± 0.018 | 0.867 ± 0.003 | 1,275 | 801 |
| 1:50 | 0.112 ± 0.002 | 0.783 ± 0.014 | 0.197 ± 0.003 | 0.261 ± 0.012 | 0.875 ± 0.002 | 6,368 | 807 |
| 1:100 | 0.059 ± 0.001 | 0.780 ± 0.011 | 0.110 ± 0.002 | 0.160 ± 0.007 | 0.876 ± 0.001 | 12,720 | 803 |

If the host-only model is much weaker, much of the full model's skill comes from the path and query. That is only trustworthy if legitimate URLs with paths are well represented in both training and testing.

## Live test by source

| set | source | urls | flagged_as_phishing |
|---|---|---|---|
| live phishing | openphish | 256 | 0.8440 |
| live phishing | openphish\|phishunt | 22 | 0.9090 |
| live phishing | phishunt | 752 | 0.7860 |
| held-back legitimate | kaggle_benign | 46,511 | 0.4320 |
| held-back legitimate | kaggle_benign\|tranco | 230 | 0.0090 |
| held-back legitimate | tranco | 105,860 | 0.0140 |
