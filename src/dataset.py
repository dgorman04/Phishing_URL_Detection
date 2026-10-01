"""Building training sets, fitting trees, choosing thresholds and scoring.

Shared by the improvement experiments (src/experiments.py), the final model
(src/train_eval.py) and the feature analysis (src/analysis.py), so every step uses the
same data and the same test set.
"""
from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import GridSearchCV, GroupKFold
from sklearn.tree import DecisionTreeClassifier

from .config import ALLOWLIST_TOP, MAX_URLS_PER_SITE, PROCESSED, SEED, TUNE_FOLDS
from .features import BASE_FEATURES, FEATURES
from .integrate import _hash01

VAL_PHISH_FRACTION = 0.15  # share of phishing sites held out of training to pick thresholds

TREE_GRID = {
    "criterion": ["gini", "entropy"],
    "max_depth": [8, 12, 16, 20, 25, None],
    "min_samples_leaf": [5, 20, 50, 100, 200],
}
PRUNE_GRID = {
    "criterion": ["gini", "entropy"],
    "min_samples_leaf": [5, 20, 50, 100],
    "ccp_alpha": [0.0, 1e-5, 3e-5, 1e-4, 3e-4, 1e-3],
}


@dataclass(frozen=True)
class Setup:
    """One combination of improvements. Each flag switches one change on."""
    name: str
    cap_per_site: bool = False      # at most MAX_URLS_PER_SITE URLs from any one site
    match_path_share: bool = False  # legit URLs have a path as often as phishing URLs do
    use_commoncrawl: bool = False   # add current legitimate deep links from Common Crawl
    clean_labels: bool = False      # drop legitimate URLs flagged as suspect labels
    new_features: bool = False      # add the 8 new features
    prune: bool = False             # cost-complexity pruning, smallest tree within 1 SE
    tune_threshold: bool = False    # threshold chosen on validation data at 1:100
    allowlist: bool = False         # Tranco top-N registered domains are always legitimate
    model: str = "tree"             # "tree" or "forest"
    feature_set: tuple = ()         # overrides the feature list (used for the host-only check)

    @property
    def features(self):
        if self.feature_set:
            return list(self.feature_set)
        return FEATURES if self.new_features else BASE_FEATURES

    def model_key(self):
        """Settings that change the fitted model (threshold and allowlist do not)."""
        return (self.cap_per_site, self.match_path_share, self.use_commoncrawl,
                self.clean_labels, self.new_features, self.prune, self.model, self.feature_set)


def _cumulative():
    steps = [
        ("Baseline (before improvements)", {}),
        ("+ cap of 20 URLs per site", {"cap_per_site": True}),
        ("+ legit path share matched to phishing", {"match_path_share": True}),
        ("+ Common Crawl deep links", {"use_commoncrawl": True}),
        ("+ suspect labels removed", {"clean_labels": True}),
        ("+ 8 new features", {"new_features": True}),
        ("+ cost-complexity pruning", {"prune": True}),
        ("+ threshold tuned on validation", {"tune_threshold": True}),
        (f"+ allowlist (Tranco top {ALLOWLIST_TOP:,})", {"allowlist": True}),
    ]
    out, flags = [], {}
    for name, f in steps:
        flags = {**flags, **f}
        out.append(Setup(name, **flags))
    return out


LADDER = _cumulative()
FINAL = LADDER[-1]
FOREST = Setup("Random forest, same data, features, threshold and allowlist",
               **{**{k: getattr(FINAL, k) for k in FINAL.__dataclass_fields__ if k != "name"},
                  "prune": False, "model": "forest"})


def load_features() -> pd.DataFrame:
    return pd.read_csv(PROCESSED / "features.csv", keep_default_na=False, low_memory=False)


def has_path(df: pd.DataFrame) -> pd.Series:
    return (df["path_length"] > 0) | (df["query_length"] > 0)


def is_val_phish(df: pd.DataFrame) -> pd.Series:
    """Phishing training-source URLs held out (by site) for threshold selection."""
    return (df["role"] == "train") & (df["label"] == 1) & \
        df["site"].map(lambda s: _hash01(f"valphish{SEED}:{s}") < VAL_PHISH_FRACTION)


def build_train(df: pd.DataFrame, setup: Setup) -> pd.DataFrame:
    """Balanced training set for one setup, drawn from the training candidates."""
    c = df[(df["role"] == "train") & ~is_val_phish(df)]
    if not setup.use_commoncrawl:
        c = c[c["sources"] != "commoncrawl"]
    if setup.clean_labels:
        c = c[c["suspect_reason"] == ""]
    if setup.cap_per_site:
        c = c.sample(frac=1, random_state=SEED).groupby("site", sort=False).head(MAX_URLS_PER_SITE)
    phish, legit = c[c["label"] == 1], c[c["label"] == 0]
    n = min(len(phish), len(legit))
    phish = phish.sample(n, random_state=SEED)
    if setup.match_path_share:
        target = has_path(phish).mean()
        lp, ln = legit[has_path(legit)], legit[~has_path(legit)]
        n_p = min(int(round(n * target)), len(lp))
        n_n = min(n - n_p, len(ln))
        legit = pd.concat([lp.sample(n_p, weights="pool_weight", random_state=SEED),
                           ln.sample(n_n, weights="pool_weight", random_state=SEED)])
    else:
        legit = legit.sample(n, weights="pool_weight", random_state=SEED)
    return pd.concat([phish, legit]).sample(frac=1, random_state=SEED).reset_index(drop=True)


def _one_se_choice(search) -> dict:
    """Smallest tree whose CV score is within one standard error of the best."""
    r = pd.DataFrame(search.cv_results_)
    best = r["mean_test_score"].max()
    se = r.loc[r["mean_test_score"].idxmax(), "std_test_score"] / np.sqrt(TUNE_FOLDS)
    ok = r[r["mean_test_score"] >= best - se]
    ok = ok.sort_values(["param_ccp_alpha", "param_min_samples_leaf"], ascending=False)
    return ok.iloc[0]["params"], float(ok.iloc[0]["mean_test_score"])


def fit(train: pd.DataFrame, setup: Setup):
    """Fit the model for a setup. Returns (model, chosen parameters, CV average precision)."""
    X, y, groups = train[setup.features], train["label"], train["reg_domain"]
    if setup.model == "forest":
        model = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1,
                                       random_state=SEED).fit(X, y)
        return model, {"n_estimators": 300, "min_samples_leaf": 2}, float("nan")
    grid = PRUNE_GRID if setup.prune else TREE_GRID
    search = GridSearchCV(DecisionTreeClassifier(random_state=SEED), grid, scoring="average_precision",
                          cv=GroupKFold(n_splits=TUNE_FOLDS), refit=not setup.prune)
    # Tree fitting releases the GIL, so threads parallelise well and avoid Windows
    # process-pool problems.
    with joblib.parallel_backend("threading", n_jobs=-1):
        search.fit(X, y, groups=groups)
    if not setup.prune:
        return search.best_estimator_, search.best_params_, float(search.best_score_)
    params, score = _one_se_choice(search)
    model = DecisionTreeClassifier(random_state=SEED, **params).fit(X, y)
    return model, params, score


def allowlisted(df: pd.DataFrame) -> np.ndarray:
    """Registered domain in the Tranco top N, unless the site is on a free hosting platform.
    weebly.com or godaddysites.com rank highly, but anyone can publish a site on them, so
    their popularity says nothing about a particular hosted site."""
    return (df["tranco_rank"].between(1, ALLOWLIST_TOP) & (df["free_hosting"] == 0)).to_numpy()


def scores(model, df: pd.DataFrame, setup: Setup) -> np.ndarray:
    prob = model.predict_proba(df[setup.features])[:, 1]
    if setup.allowlist:
        prob = np.where(allowlisted(df), 0.0, prob)
    return prob


def choose_threshold(model, df: pd.DataFrame, setup: Setup, ratio: int = 100) -> float:
    """Threshold that maximises F1 on validation data at the given legit:phishing ratio.

    Validation = phishing sites held out of training + the validation pool of held-back
    legitimate domains. The test set is never used.
    """
    if not setup.tune_threshold:
        return 0.5
    vp = df[is_val_phish(df)]
    vl = df[df["role"] == "val_legit_pool"]
    n = min(len(vp), len(vl) // ratio)
    v = pd.concat([vp.sample(n, random_state=SEED), vl.sample(n * ratio, random_state=SEED)])
    prec, rec, thr = precision_recall_curve(v["label"], scores(model, v, setup))
    f1 = 2 * prec[:-1] * rec[:-1] / np.clip(prec[:-1] + rec[:-1], 1e-12, None)
    return float(thr[int(np.argmax(f1))])


def evaluate(prob: np.ndarray, y: np.ndarray, thr: float) -> dict:
    pred = (prob >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "avg_precision": average_precision_score(y, prob), "accuracy": (tp + tn) / len(y),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def live_test(prob_phish: np.ndarray, prob_pool: np.ndarray, thr: float, ratios, repeats: int,
              seed: int = SEED, keep_curves: bool = False):
    """Mix live phishing with held-back legitimate URLs at each ratio, many times.

    Each repeat draws a fresh legitimate sample and bootstraps the phishing URLs. Scores are
    computed once, so repeats are cheap.
    """
    rng = np.random.default_rng(seed)
    n, rows, curves = len(prob_phish), [], {}
    for ratio in ratios:
        k = min(n * ratio, len(prob_pool))
        for rep in range(repeats):
            pp = prob_phish[rng.choice(n, n, replace=True)]
            pl = prob_pool[rng.choice(len(prob_pool), k, replace=False)]
            prob = np.concatenate([pp, pl])
            y = np.concatenate([np.ones(n, int), np.zeros(k, int)])
            rows.append({"ratio": f"1:{ratio}", "repeat": rep, **evaluate(prob, y, thr)})
            if keep_curves and rep == 0:
                p, r, _ = precision_recall_curve(y, prob)
                curves[ratio] = (p, r, rows[-1]["avg_precision"])
    out = pd.DataFrame(rows)
    return (out, curves) if keep_curves else out
