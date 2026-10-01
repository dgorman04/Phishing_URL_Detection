"""Step 5: train the decision tree and evaluate it.

  - Split by registered domain (GroupShuffleSplit / GroupKFold) so URLs from one
    domain never sit in both train and test.
  - Tune depth, leaf size and split criterion (Gini vs entropy) with 5-fold
    grouped cross-validation, scored by average precision.
  - Evaluate on the held-out domains, then on live phishing URLs never seen in
    training mixed with held-back legitimate URLs at 1:1, 1:10, 1:50 and 1:100.
  - Report precision, recall, F1 and PR curves. Accuracy is shown only to show
    why it misleads under imbalance.
  - Repeat with host-only features to check how much the model leans on the path.

Output: models/decision_tree.joblib, reports/results_report.md, reports/tree_rules.txt,
reports/metrics.json, reports/figures/*.png
"""
import json

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve, precision_score, recall_score)
from sklearn.model_selection import GridSearchCV, GroupKFold, GroupShuffleSplit
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree

from .analysis import INK, LEGIT, MUTED, PHISH, style
from .config import FIGURES, PROCESSED, RATIO_REPEATS, RATIOS, REPORTS, ROOT, SEED
from .features import FEATURES, HOST_FEATURES
from .integrate import md_table

RATIO_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # validated categorical slots 1-4
PARAM_GRID = {
    "criterion": ["gini", "entropy"],
    "max_depth": [4, 6, 8, 10, 12, 16, 20, 25, None],
    "min_samples_leaf": [1, 5, 20, 50, 100, 200],
}


def metrics(y, prob, thr=0.5):
    pred = (prob >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0),
            "f1": f1_score(y, pred, zero_division=0),
            "avg_precision": average_precision_score(y, prob),
            "accuracy": accuracy_score(y, pred),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}


def fit(train, feats):
    X, y, groups = train[feats], train["label"], train["reg_domain"]
    search = GridSearchCV(DecisionTreeClassifier(random_state=SEED), PARAM_GRID,
                          scoring="average_precision", cv=GroupKFold(n_splits=5), n_jobs=1)
    search.fit(X, y, groups=groups)
    return search


def live_eval(model, feats, test_phish, pool, rng, curves=None):
    rows = []
    n = len(test_phish)
    for ratio in RATIOS:
        k = min(n * ratio, len(pool))
        for rep in range(RATIO_REPEATS):
            # Bootstrap the phishing URLs too, so the spread reflects uncertainty in recall
            phish = test_phish.iloc[rng.choice(n, n, replace=True)]
            legit = pool.iloc[rng.choice(len(pool), k, replace=False)]
            t = pd.concat([phish, legit])
            prob = model.predict_proba(t[feats])[:, 1]
            m = metrics(t["label"].to_numpy(), prob)
            rows.append({"ratio": f"1:{ratio}", "repeat": rep, **m})
            if curves is not None and rep == 0:
                curves[ratio] = precision_recall_curve(t["label"], prob)[:2] + (m["avg_precision"],)
    return pd.DataFrame(rows)


def summarise(live):
    cols = ["precision", "recall", "f1", "avg_precision", "accuracy", "fp", "tp"]
    g = live.groupby("ratio", sort=False)[cols]
    mean, std = g.mean(), g.std()
    out = pd.DataFrame(index=mean.index)
    for c in ["precision", "recall", "f1", "avg_precision", "accuracy"]:
        out[c] = [f"{a:.3f} ± {b:.3f}" for a, b in zip(mean[c], std[c])]
    out["false_positives"] = mean["fp"].round(0).astype(int)
    out["phishing_caught"] = mean["tp"].round(0).astype(int)
    return out.reset_index()


def main():
    df = pd.read_csv(PROCESSED / "features.csv", keep_default_na=False)
    data = df[df["role"] == "train"].reset_index(drop=True)
    test_phish = df[(df["role"] == "test") & (df["label"] == 1)]
    pool = df[df["role"] == "test_legit_pool"]

    # Hold out 20% of domains for an in-distribution test
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    dev_idx, hold_idx = next(gss.split(data, data["label"], groups=data["reg_domain"]))
    dev, hold = data.iloc[dev_idx], data.iloc[hold_idx]
    assert not set(dev["reg_domain"]) & set(hold["reg_domain"])

    results = {}
    report = ["# Results", ""]
    for name, feats in (("all_features", FEATURES), ("host_only", HOST_FEATURES)):
        print(f"Tuning decision tree ({name}) ...")
        search = fit(dev, feats)
        model = search.best_estimator_
        hold_m = metrics(hold["label"].to_numpy(), model.predict_proba(hold[feats])[:, 1])
        curves = {} if name == "all_features" else None
        live = live_eval(model, feats, test_phish, pool, np.random.default_rng(SEED), curves)
        results[name] = {"best_params": search.best_params_, "cv_avg_precision": search.best_score_,
                         "holdout": hold_m, "live": live.groupby("ratio", sort=False).mean(numeric_only=True)
                         .drop(columns="repeat").to_dict(orient="index"),
                         "depth": model.get_depth(), "leaves": model.get_n_leaves()}
        if name == "all_features":
            main_model, main_curves, main_live, main_hold = model, curves, live, hold_m
        else:
            host_live, host_hold = live, hold_m

    # --- Recall per live feed, and false-positive rate per legitimate source -----
    tp_pred = main_model.predict(test_phish[FEATURES])
    pool_pred = main_model.predict(pool[FEATURES])
    rows = []
    for src, grp in test_phish.assign(pred=tp_pred).groupby("sources"):
        rows.append({"set": "live phishing", "source": src, "urls": len(grp),
                     "flagged_as_phishing": round(float(grp["pred"].mean()), 3)})
    for src, grp in pool.assign(pred=pool_pred).groupby("sources"):
        rows.append({"set": "held-back legitimate", "source": src, "urls": len(grp),
                     "flagged_as_phishing": round(float(grp["pred"].mean()), 3)})
    live_by_source = pd.DataFrame(rows)

    # --- Save model and rules -------------------------------------------------
    (ROOT / "models").mkdir(exist_ok=True)
    joblib.dump({"model": main_model, "features": FEATURES}, ROOT / "models" / "decision_tree.joblib")
    (REPORTS / "tree_rules.txt").write_text(export_text(main_model, feature_names=FEATURES, decimals=2),
                                            encoding="utf-8")
    (REPORTS / "metrics.json").write_text(json.dumps(results, indent=2, default=float), encoding="utf-8")

    # --- Figures --------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(7, 5))
    for (ratio, (prec, rec, ap)), color in zip(main_curves.items(), RATIO_COLORS):
        ax.plot(rec, prec, color=color, linewidth=2, label=f"1:{ratio}  (AP {ap:.3f})", drawstyle="steps-post")
    ax.set_xlabel("Recall (share of phishing caught)", color=INK)
    ax.set_ylabel("Precision (share of alerts that are phishing)", color=INK)
    ax.set_xlim(0, 1.01)
    ax.set_ylim(0, 1.02)
    ax.set_title("Precision-recall on live phishing URLs at each legit:phishing ratio",
                 loc="left", fontsize=11, color=INK)
    ax.legend(frameon=False, fontsize=9, title="legit:phishing", title_fontsize=9, loc="lower left")
    style(ax)
    fig.tight_layout()
    fig.savefig(FIGURES / "pr_curves.png", dpi=150)
    plt.close(fig)

    imp = pd.Series(main_model.feature_importances_, index=FEATURES).sort_values()
    imp = imp[imp > 0]
    fig, ax = plt.subplots(figsize=(7, 0.3 * len(imp) + 1.2))
    ax.barh(imp.index, imp.values, color=LEGIT, height=0.6)
    ax.set_xlabel("Gini importance (share of total impurity reduction)", color=INK)
    ax.set_title("What the tree relies on", loc="left", fontsize=11, color=INK)
    style(ax)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "feature_importance.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(18, 8))
    plot_tree(main_model, max_depth=3, feature_names=FEATURES, class_names=["legit", "phish"],
              filled=False, impurity=True, proportion=True, rounded=True, fontsize=8, ax=ax)
    ax.set_title("Top 4 levels of the decision tree (full rules in reports/tree_rules.txt)",
                 loc="left", fontsize=12, color=INK)
    fig.tight_layout()
    fig.savefig(FIGURES / "tree_top_levels.png", dpi=130)
    plt.close(fig)

    # --- Report ---------------------------------------------------------------
    def hold_table(m):
        return md_table(pd.DataFrame([{k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()}]))

    main_sum, host_sum = summarise(main_live), summarise(host_live)

    def path_share(frame):
        return float(((frame["path_length"] > 0) | (frame["query_length"] > 0)).mean())
    legit_path_train = path_share(data[data["label"] == 0])
    phish_path_train = path_share(data[data["label"] == 1])
    legit_path_pool = path_share(pool)
    r_all, r_host = results["all_features"], results["host_only"]
    report += [
        f"Training data: {len(data):,} URLs (balanced). Held-out domains: {len(hold):,} URLs. "
        f"Live phishing test URLs: {len(test_phish):,}. Held-back legitimate pool: {len(pool):,}.", "",
        "## Chosen tree", "",
        f"Grouped 5-fold cross-validation picked {r_all['best_params']} "
        f"(CV average precision {r_all['cv_avg_precision']:.4f}). "
        f"The tree has depth {r_all['depth']} and {r_all['leaves']} leaves.", "",
        "## Held-out domains (balanced, same sources as training)", "",
        hold_table(main_hold), "",
        "## Live phishing URLs at realistic imbalance", "",
        f"Mean ± standard deviation over {RATIO_REPEATS} draws. Each draw takes a fresh random sample of "
        "legitimate URLs and a bootstrap resample of the phishing URLs. "
        "Threshold 0.5. Accuracy is shown only for contrast: at 1:100 a model that flags nothing "
        "already scores 0.990.", "",
        md_table(main_sum), "",
        "![pr](figures/pr_curves.png)", "",
        "![importance](figures/feature_importance.png)", "",
        "![tree](figures/tree_top_levels.png)", "",
        "## Robustness check: host-only features", "",
        f"Share of legitimate URLs with a path or query: {legit_path_train:.1%} in training, "
        f"{legit_path_pool:.1%} in the held-back test pool, against {phish_path_train:.1%} of "
        "training phishing URLs. Where these differ a lot, path features become a shortcut. "
        f"This model uses only features of the host name: {', '.join(HOST_FEATURES)}.", "",
        f"Best parameters {r_host['best_params']}, depth {r_host['depth']}.", "",
        hold_table(host_hold), "",
        md_table(host_sum), "",
        "If the host-only model is much weaker, much of the full model's skill comes from the "
        "path and query. That is only trustworthy if legitimate URLs with paths are well "
        "represented in both training and testing.", "",
        "## Live test by source", "",
        md_table(live_by_source), ""]
    (REPORTS / "results_report.md").write_text("\n".join(report), encoding="utf-8")

    print("\nAll features, held-out domains:", {k: round(v, 4) for k, v in main_hold.items() if isinstance(v, float)})
    print(main_sum.to_string(index=False))
    print("\nHost only, held-out domains:", {k: round(v, 4) for k, v in host_hold.items() if isinstance(v, float)})
    print(host_sum.to_string(index=False))


if __name__ == "__main__":
    main()
