# Data integration report

## 1. Rows per source

| source | raw_rows | malformed | exact_duplicates_in_source | same_entity_in_source |
|---|---|---|---|---|
| kaggle_benign | 428,103 | 159 | 22 | 1,948 |
| openphish | 900 | 0 | 600 | 20 |
| phishing_database | 50,000 | 21 | 0 | 60 |
| phishunt | 2,322 | 0 | 1,545 | 0 |
| tranco | 1,000,000 | 0 | 0 | 0 |
| url_phish | 116,600 | 1 | 1,369 | 967 |

## 2. Malformed URLs by reason

| source | bad_host | non_http_scheme | too_long | whitespace |
|---|---|---|---|---|
| kaggle_benign | 3 | 12 | 2 | 142 |
| phishing_database | 0 | 1 | 20 | 0 |
| url_phish | 0 | 0 | 0 | 1 |

## 3. Entity identification

20,317 URLs were written in more than one way and were merged into one entity after normalisation (scheme dropped, host lower-cased, 'www.' removed, default port, fragment and trailing '/' removed).

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

17,963 distinct URLs appear in two or more sources.

| sources | urls |
|---|---|
| tranco\|url_phish | 14,955 |
| kaggle_benign\|tranco | 2,471 |
| kaggle_benign\|tranco\|url_phish | 332 |
| kaggle_benign\|url_phish | 158 |
| openphish\|phishunt | 22 |
| phishing_database\|url_phish | 17 |
| phishing_database\|tranco | 3 |
| phishing_database\|phishunt | 2 |
| openphish\|url_phish | 1 |
| phishunt\|tranco | 1 |

## 5. Value conflicts (label disagreements)

8 URLs are labelled phishing by one source and legitimate by another. Resolution rule: the phishing label wins. All conflicts are listed in data/processed/label_conflicts.csv.

| sources | urls |
|---|---|
| tranco\|url_phish | 4 |
| phishing_database\|tranco | 3 |
| phishunt\|tranco | 1 |

## 6. Train / test separation

- Live-feed URLs removed from the test set because they already appear in a training source: 5
- Held-back legitimate URLs removed because their domain appears in training: 1,899
- Live phishing test URLs whose registered domain also appears in training (kept, e.g. shared hosting): 84

- Legitimate URLs dropped from training because their domain was held back for testing: 8,086

Held-back legitimate test pool by source:

| sources | urls |
|---|---|
| tranco | 105,860 |
| kaggle_benign | 46,511 |
| kaggle_benign\|tranco | 230 |

## 7. Final dataset

| role | label | rows |
|---|---|---|
| test | 1 | 1,030 |
| test_legit_pool | 0 | 152,601 |
| train | 0 | 66,092 |
| train | 1 | 66,092 |
