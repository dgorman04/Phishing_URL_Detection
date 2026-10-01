# Feature analysis (training set)

132,184 training URLs, 66,092 phishing and 66,092 legitimate.

## Gini gain and information gain of the best single split

Each value is how much one threshold on that feature alone reduces impurity at the root of a tree. Higher means the feature separates the classes better on its own.

| feature | info_gain | gini_gain | best_threshold |
|---|---|---|---|
| url_length | 0.2411 | 0.1564 | 21.5000 |
| entropy | 0.2402 | 0.1555 | 3.6423 |
| num_dots | 0.1921 | 0.1271 | 1.5000 |
| host_length | 0.1562 | 0.1012 | 20.5000 |
| path_length | 0.1506 | 0.1006 | 1.0000 |
| path_depth | 0.1506 | 0.1006 | 0.5000 |
| digit_ratio | 0.1395 | 0.0932 | 0.0003 |
| digit_count | 0.1395 | 0.0932 | 0.5000 |
| host_entropy | 0.1316 | 0.0860 | 3.6423 |
| num_subdomains | 0.1215 | 0.0778 | 0.5000 |
| num_hyphens | 0.0820 | 0.0553 | 0.5000 |
| host_hyphens | 0.0792 | 0.0521 | 0.5000 |
| suspicious_word_count | 0.0745 | 0.0460 | 0.5000 |
| host_digits | 0.0618 | 0.0408 | 0.5000 |
| query_length | 0.0381 | 0.0244 | 10.5000 |
| num_params | 0.0376 | 0.0243 | 0.5000 |
| special_char_count | 0.0295 | 0.0199 | 0.5000 |
| is_shortener | 0.0120 | 0.0064 | 0.5000 |
| has_at | 0.0066 | 0.0037 | 0.5000 |
| ip_host | 0.0044 | 0.0023 | 0.5000 |
| has_port | 0.0005 | 0.0003 | 0.5000 |
| has_punycode | 0.0001 | 0.0001 | 0.5000 |

![ranking](figures/feature_ranking.png)

![distributions](figures/feature_distributions.png)

## Redundancy and correlation

Feature pairs with |Pearson r| >= 0.8 carry largely the same information. A decision tree copes with this, but redundant pairs split the importance between them, which makes the importance ranking harder to read.

| feature_a | feature_b | pearson_r |
|---|---|---|
| url_length | query_length | 0.8650 |
| url_length | digit_count | 0.8240 |

![correlation](figures/correlation_heatmap.png)

## Shortcut check: share of URLs with a path or query

Tranco and URL-Phish list legitimate sites as bare domains or homepages, while the Kaggle benign URLs are mostly deep links. If legitimate URLs rarely had a path, a tree could learn 'has a path means phishing', which fails on real traffic. The tables below show how balanced this is, and the host-only model in the results report checks how much performance depends on the path.

| label | has_path_or_query |
|---|---|
| legitimate | 0.2510 |
| phishing | 0.7110 |

| sources | label | mean | size |
|---|---|---|---|
| phishing_database | 1 | 0.7540 | 49,896 |
| tranco | 0 | 0.0000 | 41,367 |
| kaggle_benign | 0 | 0.8890 | 16,899 |
| url_phish | 1 | 0.5790 | 16,167 |
| url_phish | 0 | 0.2450 | 6,408 |
| tranco\|url_phish | 0 | 0.0000 | 1,267 |
| kaggle_benign\|tranco | 0 | 0.0000 | 104 |
| kaggle_benign\|tranco\|url_phish | 0 | 0.0000 | 33 |

Per-feature means and medians by class are in reports/feature_summary.csv.
