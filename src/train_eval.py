"""Step 6: train the final decision tree and evaluate it.

Uses every improvement from the experiments (src/dataset.py: FINAL):
  - per-site cap, matched path share, Common Crawl deep links, cleaned labels
  - 30 features, cost-complexity pruning (one-standard-error rule)
  - threshold chosen on validation data at 1:100, Tranco top-10k allowlist

Then:
  - held-out domains (balanced) and live phishing at 1:1, 1:10, 1:50, 1:100
  - precision-recall curves, feature importance, the top of the tree
  - host-only robustness check
  - error analysis of false positives and missed phishing
  - performance by the date each live phishing URL first appeared

Output: models/decision_tree.joblib, reports/results_report.md, reports/tree_rules.txt,
reports/metrics.json, reports/error_examples.csv, reports/figures/*.png, and the error
analysis and over-time sections of reports/analysis_report.md
"""
import json
from dataclasses import replace

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.tree import export_text, plot_tree

from .analysis import INK, LEGIT, MUTED, style
from .config import (ALLOWLIST_TOP, FIGURES, RATIO_REPEATS, RATIOS, RAW, REPORTS, ROOT, SEED)
from .dataset import (FINAL, build_train, choose_threshold, evaluate, fit, live_test,
                      load_features, scores)
from .features import HOST_FEATURES
from .integrate import md_table
from .reporting import splice_section
from .urlutils import registered_domain

RATIO_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # validated categorical slots 1-4

# Error categories: the first rule that matches wins
FP_RULES = [
    ("IP address as host", lambda r: r["ip_host"] == 1),
    ("Site on a free hosting platform", lambda r: r["free_hosting"] == 1),
    ("Brand name outside its own domain", lambda r: r["brand_outside_domain"] == 1),
    ("Phishing-style words (login, account, verify...)", lambda r: r["suspicious_word_count"] > 0),
    ("Long random-looking ID in path or query", lambda r: r["longest_token"] >= 20 or r["digit_ratio"] > 0.2),
    ("Suspicious top-level domain", lambda r: r["suspicious_tld"] == 1),
    ("Two or more subdomains", lambda r: r["num_subdomains"] >= 2),
    ("Long URL (over 80 characters)", lambda r: r["url_length"] > 80),
    ("Other", lambda r: True),
]
FN_RULES = [
    (f"On a popular domain, so allowlisted (Tranco top {ALLOWLIST_TOP:,})",
     lambda r: 1 <= r["tranco_rank"] <= ALLOWLIST_TOP and r["free_hosting"] == 0),
    ("Site on a free hosting platform", lambda r: r["free_hosting"] == 1),
    ("URL shortener", lambda r: r["is_shortener"] == 1),
    ("Homepage only, no path or query", lambda r: r["path_length"] == 0 and r["query_length"] == 0),
    ("Short, clean-looking URL (under 40 characters)", lambda r: r["url_length"] < 40),
    ("Other", lambda r: True),
]


def categorise(rows: pd.DataFrame, rules) -> pd.Series:
    def first(r):
        return next(name for name, rule in rules if rule(r))
    return rows.apply(first, axis=1) if len(rows) else pd.Series(dtype=str)


def summarise(live: pd.DataFrame) -> pd.DataFrame:
    g = live.groupby("ratio", sort=False)
    mean, std = g.mean(numeric_only=True), g.std(numeric_only=True)
    out = pd.DataFrame(index=mean.index)
    for c in ["precision", "recall", "f1", "avg_precision", "accuracy"]:
        out[c] = [f"{a:.3f} ± {b:.3f}" for a, b in zip(mean[c], std[c])]
    out["false_positives"] = mean["fp"].round(0).astype(int)
    out["phishing_caught"] = mean["tp"].round(0).astype(int)
    return out.reset_index()


def one_row(m: dict) -> str:
    return md_table(pd.DataFrame([{k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()}]))


def main():
    df = load_features()
    setup = FINAL
    feats = setup.features
    data = build_train(df, setup)
    test_phish = df[(df["role"] == "test") & (df["label"] == 1)].reset_index(drop=True)
    pool = df[df["role"] == "test_legit_pool"].reset_index(drop=True)

    # Hold out 20% of domains for an in-distribution check
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    dev_idx, hold_idx = next(gss.split(data, data["label"], groups=data["reg_domain"]))
    dev, hold = data.iloc[dev_idx], data.iloc[hold_idx]

    results, report = {}, ["# Results (final model)", ""]
    print("Fitting the final tree ...")
    # The in-distribution check needs a model that has not seen the held-out domains
    dev_model, _, _ = fit(dev, setup)
    hold_m = evaluate(scores(dev_model, hold, setup), hold["label"].to_numpy(),
                      choose_threshold(dev_model, df, setup))
    # The final model uses all training data, exactly as the last experiment step
    model, params, cv = fit(data, setup)
    thr = choose_threshold(model, df, setup)
    pp, pl = scores(model, test_phish, setup), scores(model, pool, setup)
    live, curves = live_test(pp, pl, thr, RATIOS, RATIO_REPEATS, keep_curves=True)

    print("Fitting the host-only tree ...")
    host_setup = replace(setup, name="host only", feature_set=tuple(HOST_FEATURES))
    h_dev, _, _ = fit(dev, host_setup)
    h_hold = evaluate(scores(h_dev, hold, host_setup), hold["label"].to_numpy(),
                      choose_threshold(h_dev, df, host_setup))
    h_model, h_params, h_cv = fit(data, host_setup)
    h_thr = choose_threshold(h_model, df, host_setup)
    h_live = live_test(scores(h_model, test_phish, host_setup), scores(h_model, pool, host_setup),
                       h_thr, RATIOS, RATIO_REPEATS)

    for name, m, p, c, t, lv, hm in (("final", model, params, cv, thr, live, hold_m),
                                     ("host_only", h_model, h_params, h_cv, h_thr, h_live, h_hold)):
        results[name] = {"params": p, "cv_avg_precision": c, "threshold": t, "holdout": hm,
                         "depth": int(m.get_depth()), "leaves": int(m.get_n_leaves()),
                         "live": lv.groupby("ratio", sort=False).mean(numeric_only=True)
                         .drop(columns="repeat").to_dict(orient="index")}

    # --- Save the model with what predict.py needs ---------------------------------
    t = pd.read_csv(RAW / "tranco_top1m.csv.zip", header=None, names=["rank", "domain"], nrows=ALLOWLIST_TOP)
    allow = sorted(set(("https://" + t["domain"].astype(str) + "/").map(registered_domain)))
    (ROOT / "models").mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": feats, "threshold": thr, "allowlist": allow},
                ROOT / "models" / "decision_tree.joblib")
    (REPORTS / "tree_rules.txt").write_text(export_text(model, feature_names=feats, decimals=2),
                                            encoding="utf-8")
    (REPORTS / "metrics.json").write_text(json.dumps(results, indent=2, default=float), encoding="utf-8")

    # --- Figures -----------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(7, 5))
    for (ratio, (prec, rec, ap)), color in zip(curves.items(), RATIO_COLORS):
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

    imp = pd.Series(model.feature_importances_, index=feats).sort_values()
    imp = imp[imp > 0]
    fig, ax = plt.subplots(figsize=(7, 0.3 * len(imp) + 1.2))
    ax.barh(imp.index, imp.values, color=LEGIT, height=0.6)
    ax.set_xlabel("Gini importance (share of total impurity reduction)", color=INK)
    ax.set_title("What the final tree relies on", loc="left", fontsize=11, color=INK)
    style(ax)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "feature_importance.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(18, 8))
    plot_tree(model, max_depth=3, feature_names=feats, class_names=["legit", "phish"],
              filled=False, impurity=True, proportion=True, rounded=True, fontsize=8, ax=ax)
    ax.set_title("Top 4 levels of the final decision tree (full rules in reports/tree_rules.txt)",
                 loc="left", fontsize=12, color=INK)
    fig.tight_layout()
    fig.savefig(FIGURES / "tree_top_levels.png", dpi=130)
    plt.close(fig)

    # --- Per-source results ---------------------------------------------------------
    rows = []
    for src, grp in test_phish.assign(flag=pp >= thr).groupby("sources"):
        rows.append({"set": "live phishing", "source": src, "urls": len(grp),
                     "flagged_as_phishing": round(float(grp["flag"].mean()), 3)})
    for src, grp in pool.assign(flag=pl >= thr).groupby("sources"):
        rows.append({"set": "held-back legitimate", "source": src, "urls": len(grp),
                     "flagged_as_phishing": round(float(grp["flag"].mean()), 3)})
    by_source = pd.DataFrame(rows)

    # --- Error analysis -----------------------------------------------------------------
    fps = pool[pl >= thr].copy()
    fns = test_phish[pp < thr].copy()
    fps["category"] = categorise(fps, FP_RULES)
    fns["category"] = categorise(fns, FN_RULES)
    fp_tab = (fps["category"].value_counts().rename_axis("category").reset_index(name="false positives"))
    fp_tab["share"] = (fp_tab["false positives"] / max(len(fps), 1)).map("{:.0%}".format)
    fn_tab = (fns["category"].value_counts().rename_axis("category").reset_index(name="missed phishing"))
    fn_tab["share"] = (fn_tab["missed phishing"] / max(len(fns), 1)).map("{:.0%}".format)
    examples = pd.concat([
        fps.sample(min(100, len(fps)), random_state=SEED).assign(error="false positive"),
        fns.sample(min(100, len(fns)), random_state=SEED).assign(error="missed phishing")])
    examples[["error", "category", "url", "sources"]].to_csv(REPORTS / "error_examples.csv", index=False)
    def short(u, n=110):
        return u if len(u) <= n else u[:n] + "..."
    fp_examples = fps.groupby("category").head(2)[["category", "url"]].head(12)
    fn_examples = fns.groupby("category").head(2)[["category", "url"]].head(12)
    fp_examples["url"] = fp_examples["url"].map(short)
    fn_examples["url"] = fn_examples["url"].map(short)
    fp_suspect = float((fps["suspect_reason"] != "").mean()) if len(fps) else 0.0
    fp_rate = len(fps) / max(len(pool), 1)

    # --- Over time: by the snapshot each live URL first appeared in -----------------
    time_rows = []
    for day, idx in test_phish.groupby("seen").groups.items():
        sub = live_test(pp[np.asarray(list(idx))], pl, thr, [100], RATIO_REPEATS)
        mean = sub.mean(numeric_only=True)
        time_rows.append({"first seen": day or "unknown", "phishing URLs": len(idx),
                          "recall": f"{mean['recall']:.3f}",
                          "precision 1:100": f"{mean['precision']:.3f}",
                          "F1 1:100": f"{mean['f1']:.3f}"})
    over_time = pd.DataFrame(time_rows)

    # --- Results report ---------------------------------------------------------------
    r = results["final"]
    report += [
        f"Training data: {len(data):,} URLs (balanced). The final model is fitted on all of it. "
        f"The held-out check refits on {len(dev):,} URLs and tests on {len(hold):,} URLs from "
        f"domains it has not seen. Live phishing test URLs: {len(test_phish):,}. Held-back legitimate "
        f"test pool: {len(pool):,} URLs from {pool['reg_domain'].nunique():,} domains.", "",
        "## Final tree", "",
        f"Settings chosen by grouped cross-validation with pruning: {r['params']} "
        f"(CV average precision {r['cv_avg_precision']:.4f}). Depth {r['depth']}, {r['leaves']} leaves. "
        f"Decision threshold {thr:.3f}, chosen on validation data at 1:100. Domains in the Tranco "
        f"top {ALLOWLIST_TOP:,} are always treated as legitimate.", "",
        "## Held-out domains (balanced, same sources as training)", "",
        "Uses the same tuned threshold, which is set for 1:100. On balanced data that threshold is "
        "very strict, so recall here is low and precision high.", "",
        one_row(hold_m), "",
        "## Live phishing URLs at realistic imbalance", "",
        f"Mean ± standard deviation over {RATIO_REPEATS} draws. Each draw takes a fresh random "
        "sample of legitimate URLs and a bootstrap resample of the phishing URLs. Accuracy is "
        "shown only for contrast: at 1:100 a model that flags nothing already scores 0.990.", "",
        md_table(summarise(live)), "",
        "![pr](figures/pr_curves.png)", "",
        "![importance](figures/feature_importance.png)", "",
        "![tree](figures/tree_top_levels.png)", "",
        "## Live test by source", "",
        md_table(by_source), "",
        "## Robustness check: host-only features", "",
        f"Same data, pruning, threshold rule and allowlist, but only features of the host name: "
        f"{', '.join(HOST_FEATURES)}. Settings {results['host_only']['params']}, threshold {h_thr:.3f}.", "",
        one_row(h_hold), "",
        md_table(summarise(h_live)), "",
        "The gap between this and the full model is how much the path and query contribute.", ""]
    (REPORTS / "results_report.md").write_text("\n".join(report), encoding="utf-8")

    # --- Sections for the analysis report -----------------------------------------------
    splice_section(REPORTS / "analysis_report.md", "errors", "\n".join([
        "## Error analysis of the final model", "",
        f"On the full held-back test pool the final model flags {len(fps):,} of {len(pool):,} "
        f"legitimate URLs ({fp_rate:.2%}) and misses {len(fns):,} of {len(test_phish):,} live "
        "phishing URLs. Each error is put in the first category whose rule matches. 100 random "
        "examples of each kind are in reports/error_examples.csv.", "",
        "### False positives (legitimate URLs flagged as phishing)", "",
        md_table(fp_tab), "",
        f"{fp_suspect:.0%} of these false positives are suspect labels: legitimate-labelled URLs "
        "that match a phishing pattern or sit on a domain that hosts reported phishing. Many are "
        "real phishing pages wrongly labelled benign in the Kaggle data (see the examples), so "
        "the true false-positive rate is lower than the table suggests.", "",
        "Examples:", "", md_table(fp_examples) if len(fp_examples) else "None.", "",
        "### Missed phishing", "",
        md_table(fn_tab), "",
        "Examples:", "", md_table(fn_examples) if len(fn_examples) else "None.", "",
        "Missed phishing on allowlisted domains is the cost of the allowlist: attackers who abuse "
        "services on popular domains (Google Forms, Microsoft or Dropbox file shares and similar) "
        "slip through. Free hosting platforms are never allowlisted. "
        "Missed phishing that looks like a short, clean URL is the limit of URL-only detection; "
        "catching it needs the page content or domain-age data.",
    ]))
    splice_section(REPORTS / "analysis_report.md", "over_time", "\n".join([
        "## Performance over time", "",
        "Live phishing URLs grouped by the snapshot they first appeared in. The model was trained "
        "once and never updated, so later snapshots show how well it holds up as phishing "
        "campaigns change. Precision and F1 mix each group with legitimate URLs at 1:100.", "",
        md_table(over_time), "",
        "Run `python -m src.collect` daily (scripts/collect_daily.bat can be scheduled) to add "
        "more snapshots; each rerun of the pipeline then extends this table.",
    ]))

    print("\nFinal model, held-out domains:", {k: round(v, 4) for k, v in hold_m.items() if isinstance(v, float)})
    print(summarise(live).to_string(index=False))
    print("\nHost only:")
    print(summarise(h_live).to_string(index=False))
    print("\nOver time:")
    print(over_time.to_string(index=False))


if __name__ == "__main__":
    main()
