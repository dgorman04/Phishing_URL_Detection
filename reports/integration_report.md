# Data integration report

## 1. Rows per source

| source | raw_rows | malformed | exact_duplicates_in_source | same_entity_in_source |
|---|---|---|---|---|
| commoncrawl | 479,302 | 0 | 3,091 | 2,452 |
| kaggle_benign | 428,103 | 159 | 22 | 1,948 |
| openphish | 1,500 | 0 | 900 | 29 |
| phishing_database | 50,000 | 21 | 0 | 60 |
| phishunt | 3,866 | 0 | 2,996 | 0 |
| tranco | 1,000,000 | 0 | 0 | 0 |
| url_phish | 116,600 | 1 | 1,369 | 967 |

## 2. Malformed URLs by reason

| source | bad_host | non_http_scheme | too_long | whitespace |
|---|---|---|---|---|
| kaggle_benign | 3 | 12 | 2 | 142 |
| phishing_database | 0 | 1 | 20 | 0 |
| url_phish | 0 | 0 | 0 | 1 |

## 3. Entity identification

22,796 URLs were written in more than one way and were merged into one entity after normalisation (scheme dropped, host lower-cased, 'www.' removed, default port, fragment and trailing '/' removed).

Examples:

| key | url | source |
|---|---|---|
| 000ek4ploe.weebly.com | https://000ek4ploe.weebly.com/ | openphish |
| 000ek4ploe.weebly.com | http://www.000ek4ploe.weebly.com/ | openphish |
| 0350pc.cn/images | http://0350pc.cn/images | kaggle_benign |
| 0350pc.cn/images | http://0350pc.cn/images/ | kaggle_benign |
| 100blackmen.org | https://100blackmen.org/ | tranco |
| 100blackmen.org | http://www.100blackmen.org/ | url_phish |
| 1011now.com | https://1011now.com/ | tranco |
| 1011now.com | http://1011now.com/ | kaggle_benign |

## 4. Tuple duplication across sources

18,040 distinct URLs appear in two or more sources.

| sources | urls |
|---|---|
| tranco\|url_phish | 14,947 |
| kaggle_benign\|tranco | 2,471 |
| kaggle_benign\|tranco\|url_phish | 332 |
| kaggle_benign\|url_phish | 158 |
| commoncrawl\|tranco | 59 |
| openphish\|phishunt | 38 |
| phishing_database\|url_phish | 17 |
| commoncrawl\|url_phish | 5 |
| phishing_database\|tranco | 3 |
| commoncrawl\|tranco\|url_phish | 3 |

## 5. Value conflicts (label disagreements)

8 URLs are labelled phishing by one source and legitimate by another. Resolution rule: the phishing label wins. All conflicts are listed in data/processed/label_conflicts.csv.

| sources | urls |
|---|---|
| tranco\|url_phish | 4 |
| phishing_database\|tranco | 3 |
| phishunt\|tranco | 1 |

## 6. Train / test separation

- Live-feed URLs removed from the test set because they already appear in a training source: 5
- Held-back legitimate URLs removed because their domain appears in training: 4,252
- Live phishing test URLs whose registered domain also appears in training (kept, e.g. shared hosting): 131

- Legitimate URLs dropped from training because their domain was held back for testing: 8,091

Held-back legitimate URLs by source. The validation pool is only used to choose the decision threshold; the test pool is the final test.

| role | sources | urls |
|---|---|---|
| test_legit_pool | commoncrawl | 19,170 |
| test_legit_pool | commoncrawl\|tranco | 2 |
| test_legit_pool | kaggle_benign | 59,325 |
| test_legit_pool | kaggle_benign\|tranco | 322 |
| test_legit_pool | tranco | 128,057 |
| val_legit_pool | commoncrawl | 13,040 |
| val_legit_pool | commoncrawl\|tranco | 5 |
| val_legit_pool | kaggle_benign | 29,205 |
| val_legit_pool | kaggle_benign\|tranco | 192 |
| val_legit_pool | tranco | 76,130 |

Live phishing test URLs by the snapshot they first appeared in:

| seen | urls |
|---|---|
| 2026-09-24 | 1,030 |
| 2026-10-01 | 368 |

## 7. Common Crawl filtering

135,265 Common Crawl URLs were kept and 338,421 dropped because their domain is not in the Tranco top 1M. The kept URLs are current pages on established sites, used as legitimate deep links.

## 8. Suspect legitimate labels

Legitimate-labelled URLs on domains outside the Tranco top 100k are flagged when they match a typical phishing pattern (login, verify, webscr, WordPress PHP files and similar) or when their domain also hosts reported phishing. The label-cleaning experiment drops them.

| suspect_reason | sources | urls |
|---|---|---|
| phishing_pattern | kaggle_benign | 23,806 |
| phishing_pattern | tranco | 1,722 |
| phishing_pattern | commoncrawl | 1,163 |
| domain_hosts_phishing | tranco | 493 |
| domain_hosts_phishing | kaggle_benign | 87 |
| phishing_pattern | url_phish | 64 |
| domain_hosts_phishing | url_phish | 17 |
| domain_hosts_phishing | tranco\|url_phish | 13 |
| phishing_pattern | tranco\|url_phish | 2 |
| phishing_pattern | kaggle_benign\|tranco | 1 |

## 9. Final dataset

| role | label | rows |
|---|---|---|
| test | 1 | 1,398 |
| test_legit_pool | 0 | 206,876 |
| train | 0 | 498,542 |
| train | 1 | 66,092 |
| val_legit_pool | 0 | 118,572 |
