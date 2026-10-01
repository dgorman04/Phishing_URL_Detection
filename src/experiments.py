"""Step 5: improvement experiments.

Switches on one improvement at a time, cumulatively, and measures each step on the same
live test set: live phishing URLs never seen in training, mixed with held-back legitimate
URLs at 1:10 and 1:100. A random forest on the final setup is added for comparison.

Output: a section in reports/analysis_report.md, reports/experiments.csv,
reports/figures/improvement_steps.png
"""
import time

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .analysis import GRID, INK, LEGIT, MUTED, PHISH, style
from .config import (ALLOWLIST_TOP, FIGURES, MAX_URLS_PER_SITE, RATIO_REPEATS, REPORTS)
from .dataset import (FOREST, LADDER, build_train, choose_threshold, fit, has_path,
                      live_test, load_features, scores)
from .integrate import md_table
from .reporting import splice_section

RATIOS = [10, 100]

EXPLAIN = {
    LADDER[1].name: f"No site contributes more than {MAX_URLS_PER_SITE} URLs, so a few big sites "
                    "(Wikipedia, YouTube, phishing kits with thousands of URLs) cannot dominate "
                    "what the tree learns. Each site on a shared hosting platform counts separately.",
    LADDER[2].name: "Legitimate URLs are sampled so that the share with a path or query matches "
                    "the phishing URLs. 'Has a path' then stops being a giveaway.",
    LADDER[3].name: "Adds current pages from Common Crawl on Tranco top-1M domains, so the tree "
                    "sees what today's legitimate deep links look like.",
    LADDER[4].name: "Drops legitimate-labelled URLs that look like phishing or sit on a domain that "
                    "also hosts reported phishing (see the integration report).",
    LADDER[5].name: "Suspicious top-level domain, free hosting platform, brand name outside the "
                    "real domain, .php and .html pages, longest token, letter ratio, '//' in path.",
    LADDER[6].name: "Cost-complexity pruning with the one-standard-error rule: the smallest tree "
                    "whose cross-validated score is within one standard error of the best.",
    LADDER[7].name: "The cut-off is chosen to maximise F1 at 1:100 on validation data (held-out "
                    "phishing sites and a separate pool of held-back legitimate domains), never "
                    "on the test set.",
    LADDER[8].name: f"URLs whose registered domain is in the Tranco top {ALLOWLIST_TOP:,} are "
                    "treated as legitimate, as a deployed filter would do, except sites on free "
                    "hosting platforms (anyone can publish on weebly.com). This runs after the "
                    "tree, so it cannot leak into training.",
}


def fmt(mean, std):
    return f"{mean:.3f} ± {std:.3f}"


def main():
    df = load_features()
    test_phish = df[(df["role"] == "test") & (df["label"] == 1)]
    pool = df[df["role"] == "test_legit_pool"]
    # The same pool without legitimate-labelled URLs flagged as suspect labels. Many of these
    # are real phishing pages wrongly labelled benign in the Kaggle data, so flagging them
    # should not count as a false positive. Shown alongside, not instead: the suspect rule
    # shares words with some features, so this view is slightly optimistic.
    clean = (pool["suspect_reason"] == "").to_numpy()
    fitted, rows, src_rows = {}, [], []

    for setup in LADDER + [FOREST]:
        key = setup.model_key()
        if key not in fitted:
            t0 = time.time()
            train = build_train(df, setup)
            model, params, cv = fit(train, setup)
            fitted[key] = (model, params, cv, len(train), has_path(train[train["label"] == 0]).mean())
            print(f"  fitted '{setup.name}' on {len(train):,} URLs in {time.time() - t0:.0f}s")
        model, params, cv, n_train, legit_path = fitted[key]
        thr = choose_threshold(model, df, setup)
        pp, pl = scores(model, test_phish, setup), scores(model, pool, setup)
        live = live_test(pp, pl, thr, RATIOS, RATIO_REPEATS)
        lc = live_test(pp, pl[clean], thr, [100], RATIO_REPEATS).mean(numeric_only=True)
        g = live.groupby("ratio")
        m, s = g.mean(numeric_only=True), g.std(numeric_only=True)
        tree = setup.model == "tree"
        rows.append({
            "step": setup.name, "train_urls": n_train, "legit_with_path": legit_path,
            "leaves": int(model.get_n_leaves()) if tree else None,
            "threshold": thr, "cv_avg_precision": cv,
            "precision_1:10": m.loc["1:10", "precision"], "recall_1:10": m.loc["1:10", "recall"],
            "f1_1:10": m.loc["1:10", "f1"], "f1_1:10_sd": s.loc["1:10", "f1"],
            "precision_1:100": m.loc["1:100", "precision"], "recall_1:100": m.loc["1:100", "recall"],
            "f1_1:100": m.loc["1:100", "f1"], "f1_1:100_sd": s.loc["1:100", "f1"],
            "ap_1:100": m.loc["1:100", "avg_precision"],
            "precision_1:100_clean": lc["precision"], "f1_1:100_clean": lc["f1"],
            "params": str(params)})
        for src, grp in pool.assign(flag=pl >= thr).groupby("sources"):
            if len(grp) >= 500:
                src_rows.append({"step": setup.name, "legitimate source": src,
                                 "flagged as phishing": float(grp["flag"].mean())})
        src_rows.append({"step": setup.name, "legitimate source": "live phishing (recall)",
                         "flagged as phishing": float((pp >= thr).mean())})
        print(f"    1:100  P {rows[-1]['precision_1:100']:.3f}  R {rows[-1]['recall_1:100']:.3f}  "
              f"F1 {rows[-1]['f1_1:100']:.3f}  threshold {thr:.2f}")

    res = pd.DataFrame(rows)
    res.to_csv(REPORTS / "experiments.csv", index=False)
    ladder = res.iloc[:len(LADDER)]

    # --- Figure: precision and recall at 1:100 after each step --------------------
    fig, ax = plt.subplots(figsize=(9, 5.5))
    yy = np.arange(len(ladder))[::-1]
    h = 0.38
    ax.barh(yy + h / 2, ladder["precision_1:100"], height=h - 0.04, color=LEGIT, label="Precision")
    ax.barh(yy - h / 2, ladder["recall_1:100"], height=h - 0.04, color=PHISH, label="Recall")
    for y, p, r in zip(yy, ladder["precision_1:100"], ladder["recall_1:100"]):
        ax.text(p + 0.01, y + h / 2, f"{p:.2f}", va="center", fontsize=8, color=MUTED)
        ax.text(r + 0.01, y - h / 2, f"{r:.2f}", va="center", fontsize=8, color=MUTED)
    ax.set_yticks(yy, ladder["step"], fontsize=9)
    ax.set_xlim(0, 1.08)
    ax.set_xlabel("Live test at 1 phishing URL per 100 legitimate", color=INK)
    ax.set_title("Precision and recall after each improvement (cumulative)", loc="left",
                 fontsize=11, color=INK)
    ax.legend(frameon=False, fontsize=9, loc="lower right")
    style(ax)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "improvement_steps.png", dpi=150)
    plt.close(fig)

    # --- Report section --------------------------------------------------------------
    table = pd.DataFrame({
        "step": ladder["step"],
        "training URLs": ladder["train_urls"].astype(int),
        "legit with path": ladder["legit_with_path"].map("{:.0%}".format),
        "leaves": ladder["leaves"].astype(int),
        "threshold": ladder["threshold"].map("{:.2f}".format),
        "P 1:100": ladder["precision_1:100"].map("{:.3f}".format),
        "R 1:100": ladder["recall_1:100"].map("{:.3f}".format),
        "F1 1:100": [fmt(a, b) for a, b in zip(ladder["f1_1:100"], ladder["f1_1:100_sd"])],
        "F1 1:10": [fmt(a, b) for a, b in zip(ladder["f1_1:10"], ladder["f1_1:10_sd"])],
        "AP 1:100": ladder["ap_1:100"].map("{:.3f}".format),
        "F1 1:100, clean test": ladder["f1_1:100_clean"].map("{:.3f}".format),
    })
    changes = []
    for i in range(1, len(ladder)):
        d = ladder["f1_1:100"].iat[i] - ladder["f1_1:100"].iat[i - 1]
        changes.append(f"- **{ladder['step'].iat[i]}** (F1 at 1:100 {d:+.3f}). {EXPLAIN[ladder['step'].iat[i]]}")
    src = pd.DataFrame(src_rows).pivot(index="step", columns="legitimate source",
                                       values="flagged as phishing")
    src = src.reindex(list(res["step"])).reset_index()
    for c in src.columns[1:]:
        src[c] = src[c].map("{:.3f}".format)
    forest, final = res.iloc[-1], res.iloc[len(LADDER) - 1]
    base = res.iloc[0]
    L = ladder.set_index("step")
    cap, match, cc, cleaned, newf, pruned, thr_row = (L.loc[st.name] for st in LADDER[1:8])
    def change(a, b, col="f1_1:100", name="F1 at 1:100"):
        verb = "rose" if b[col] > a[col] + 0.0005 else "fell" if b[col] < a[col] - 0.0005 else "stayed"
        return f"{name} {verb} from {a[col]:.3f} to {b[col]:.3f}" if verb != "stayed" else \
            f"{name} stayed at {b[col]:.3f}"

    gains = (ladder["f1_1:100"].diff()).iloc[1:]
    biggest = ladder["step"].iat[int(gains.to_numpy().argmax()) + 1]
    findings = [
        f"- **Overall.** {change(base, final)}, and {change(base, final, 'precision_1:100', 'precision')}. "
        f"{change(base, final, 'recall_1:100', 'Recall')}, because a high threshold only flags URLs "
        f"the tree is very sure about. {change(base, final, 'ap_1:100', 'Average precision')}; it "
        "measures ranking quality and does not depend on the threshold.",
        f"- **The largest single gain came from: {biggest.lstrip('+ ')}.**",
        f"- **Capping URLs per site.** {change(base, cap)}. The cap trims sites with many deep links "
        f"(Kaggle, Common Crawl) but keeps every Tranco homepage, so legitimate URLs with a path went "
        f"from {base['legit_with_path']:.0%} to {cap['legit_with_path']:.0%}. That can bring back the "
        f"'has a path means phishing' shortcut. Matching the path share in the next step addresses "
        f"this: {change(cap, match)}.",
        f"- **Common Crawl deep links.** {change(match, cc)}, and "
        f"{change(match, cc, 'ap_1:100', 'average precision')}.",
        f"- **Removing suspect labels.** {change(cc, cleaned)} on the full test pool. On the clean test "
        f"pool, {change(cc, cleaned, 'f1_1:100_clean', 'F1 at 1:100')}. The bad labels matter more "
        f"for measuring the model than for training it: the final model scores "
        f"{final['f1_1:100_clean']:.3f} on the clean pool against {final['f1_1:100']:.3f} on the full "
        "pool, because some of its 'false positives' are real phishing pages labelled benign.",
        f"- **New features.** {change(cleaned, newf)}, and "
        f"{change(cleaned, newf, 'recall_1:100', 'recall')}. See the feature ranking above for "
        "which features carry the most information.",
        f"- **Pruning** shrank the tree from {int(newf['leaves'])} to {int(pruned['leaves'])} leaves, "
        f"which makes the rules far easier to read. {change(newf, pruned)}, and "
        f"{change(newf, pruned, 'ap_1:100', 'average precision')}.",
        f"- **Tuned threshold** ({thr_row['threshold']:.2f} instead of 0.5). {change(pruned, thr_row)}. "
        "With 100 legitimate URLs per phishing URL, the default 0.5 flags far too many legitimate pages.",
        "- **Order matters.** Each step is measured on top of all earlier ones, so a step's effect "
        "can differ in another order. The ± figures show sampling variation of the test set only, "
        "not variation from retraining.",
    ]

    text = "\n".join([
        "## Improvement experiments", "",
        "Each row adds one change on top of the row above. Every row is scored on the same "
        f"test set: {len(test_phish):,} live phishing URLs never seen in training, mixed with "
        f"legitimate URLs from {pool['reg_domain'].nunique():,} held-back domains. Each figure is "
        f"the mean ± standard deviation over {RATIO_REPEATS} draws (fresh legitimate sample, "
        "bootstrapped phishing). P = precision, R = recall, AP = average precision.", "",
        md_table(table), "",
        "![steps](figures/improvement_steps.png)", "",
        "'Clean test' scores the same model against the test pool without suspect labels (see "
        "the label-cleaning step).", "",
        "### Findings", "",
        *findings, "",
        "### What each step does and how much it changed F1 at 1:100", "",
        *changes, "",
        "### Share of each group flagged as phishing", "",
        "For the legitimate sources this is the false-positive rate; for live phishing it is recall.", "",
        md_table(src), "",
        "### Comparison: random forest", "",
        f"A random forest of 300 trees on the final data, features, threshold rule and allowlist "
        f"reaches F1 {forest['f1_1:100']:.3f} at 1:100 (precision {forest['precision_1:100']:.3f}, "
        f"recall {forest['recall_1:100']:.3f}), against {final['f1_1:100']:.3f} for the single tree "
        f"(precision {final['precision_1:100']:.3f}, recall {final['recall_1:100']:.3f}). "
        "The gap is the price paid for a model whose every decision can be read as a short list of rules.", "",
        "All numbers are also in reports/experiments.csv.",
    ])
    splice_section(REPORTS / "analysis_report.md", "experiments", text)
    print("Wrote the improvement section of reports/analysis_report.md")


if __name__ == "__main__":
    main()
