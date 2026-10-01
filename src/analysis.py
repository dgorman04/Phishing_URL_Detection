"""Step 4: explore the training features before modelling.

  - feature distributions per class
  - Gini gain and information gain of the best single split on each feature
    (the same criteria the decision tree uses to choose its splits)
  - correlation analysis to find redundant features (e.g. url_length vs path_length)

Output: reports/analysis_report.md, reports/figures/*.png
"""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap

from .config import FIGURES, PROCESSED, REPORTS
from .features import FEATURES
from .integrate import md_table

LEGIT, PHISH = "#2a78d6", "#eb6834"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
DIVERGING = LinearSegmentedColormap.from_list("div", [LEGIT, "#f0efec", PHISH])


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="both", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def impurity(p, kind):
    p = np.clip(p, 1e-12, 1 - 1e-12)
    if kind == "gini":
        return 2 * p * (1 - p)
    return -(p * np.log2(p) + (1 - p) * np.log2(1 - p))


def best_split(x: np.ndarray, y: np.ndarray, kind: str) -> tuple[float, float]:
    """Largest impurity decrease from one threshold on x, and that threshold."""
    order = np.argsort(x, kind="mergesort")
    xs, ys = x[order], y[order]
    n = len(y)
    cum_pos = np.cumsum(ys)
    # candidate split after position i only where the value changes
    idx = np.nonzero(np.diff(xs))[0]
    if len(idx) == 0:
        return 0.0, float("nan")
    n_left = idx + 1
    pos_left = cum_pos[idx]
    n_right = n - n_left
    pos_right = cum_pos[-1] - pos_left
    child = (n_left * impurity(pos_left / n_left, kind) + n_right * impurity(pos_right / n_right, kind)) / n
    root = impurity(cum_pos[-1] / n, kind)
    gain = root - child
    best = int(np.argmax(gain))
    thr = (xs[idx[best]] + xs[idx[best] + 1]) / 2
    return float(gain[best]), float(thr)


def main():
    from .dataset import FINAL, build_train, load_features  # late import avoids a cycle
    train = build_train(load_features(), FINAL)
    y = train["label"].to_numpy()
    lines = ["# Feature analysis", "",
             "This report analyses the training set used by the final model, after all the "
             "improvements in the experiments section below.", "",
             f"{len(train):,} training URLs, {int(y.sum()):,} phishing and {int((1 - y).sum()):,} legitimate.", ""]

    # --- 1. Distributions per class ------------------------------------------
    summary = train.groupby("label")[FEATURES].agg(["mean", "median"]).T.unstack()
    summary.columns = [f"{'legit' if lab == 0 else 'phish'}_{stat}" for lab, stat in summary.columns]
    summary = summary[["legit_mean", "phish_mean", "legit_median", "phish_median"]].round(3)
    summary.to_csv(REPORTS / "feature_summary.csv")

    # --- 2. Gini / information gain ranking ----------------------------------
    rows = []
    for f in FEATURES:
        x = train[f].to_numpy(dtype=float)
        g, thr = best_split(x, y, "gini")
        ig, _ = best_split(x, y, "entropy")
        rows.append({"feature": f, "info_gain": ig, "gini_gain": g, "best_threshold": thr})
    rank = pd.DataFrame(rows).sort_values("info_gain", ascending=False).reset_index(drop=True)
    rank.to_csv(REPORTS / "feature_ranking.csv", index=False)

    fig, ax = plt.subplots(figsize=(7, 6.5))
    r = rank.iloc[::-1]
    ax.barh(r["feature"], r["info_gain"], color=LEGIT, height=0.6)
    for yi, v in enumerate(r["info_gain"]):
        ax.text(v + 0.005, yi, f"{v:.3f}", va="center", fontsize=8, color=MUTED)
    ax.set_xlabel("Information gain of the best single split (bits)", color=INK)
    ax.set_title("Which features best separate phishing from legitimate", color=INK, loc="left", fontsize=11)
    style(ax)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "feature_ranking.png", dpi=150)
    plt.close(fig)

    # --- 3. Distributions of the top features ---------------------------------
    top = rank["feature"].head(6).tolist()
    fig, axes = plt.subplots(2, 3, figsize=(11, 6))
    for ax, f in zip(axes.ravel(), top):
        hi = np.percentile(train[f], 99)
        bins = np.linspace(train[f].min(), max(hi, train[f].min() + 1), 30)
        for lab, color, name in ((0, LEGIT, "Legitimate"), (1, PHISH, "Phishing")):
            v = train.loc[train["label"] == lab, f].clip(upper=hi)
            ax.hist(v, bins=bins, color=color, alpha=0.55, label=name,
                    weights=np.full(len(v), 1 / len(v)))
        ax.set_title(f, fontsize=10, color=INK, loc="left")
        ax.set_ylabel("share of class", fontsize=8, color=MUTED)
        style(ax)
    axes[0, 0].legend(frameon=False, fontsize=9)
    fig.suptitle("Distribution of the six most informative features (clipped at the 99th percentile)",
                 x=0.01, ha="left", fontsize=11, color=INK)
    fig.tight_layout()
    fig.savefig(FIGURES / "feature_distributions.png", dpi=150)
    plt.close(fig)

    # --- 4. Redundancy / correlation -----------------------------------------
    corr = train[FEATURES].corr()
    fig, ax = plt.subplots(figsize=(9, 8))
    im = ax.imshow(corr, cmap=DIVERGING, vmin=-1, vmax=1)
    ax.set_xticks(range(len(FEATURES)), FEATURES, rotation=90, fontsize=8)
    ax.set_yticks(range(len(FEATURES)), FEATURES, fontsize=8)
    for i in range(len(FEATURES)):
        for j in range(len(FEATURES)):
            if i != j and abs(corr.iat[i, j]) >= 0.8:
                ax.text(j, i, f"{corr.iat[i, j]:.2f}", ha="center", va="center", fontsize=6, color=INK)
    fig.colorbar(im, ax=ax, shrink=0.7, label="Pearson r")
    ax.set_title("Feature correlation (|r| >= 0.8 labelled)", color=INK, loc="left", fontsize=11)
    fig.tight_layout()
    fig.savefig(FIGURES / "correlation_heatmap.png", dpi=150)
    plt.close(fig)

    pairs = []
    for i, a in enumerate(FEATURES):
        for b in FEATURES[i + 1:]:
            r_ab = corr.loc[a, b]
            if abs(r_ab) >= 0.8:
                pairs.append({"feature_a": a, "feature_b": b, "pearson_r": round(float(r_ab), 3)})
    pairs = pd.DataFrame(pairs).sort_values("pearson_r", key=abs, ascending=False) if pairs else pd.DataFrame()

    # --- 5. Shortcut check: do legit URLs have paths at all? -----------------
    has_path = (train["path_length"] > 0) | (train["query_length"] > 0)
    shortcut = (pd.DataFrame({"label": np.where(y == 1, "phishing", "legitimate"), "has_path_or_query": has_path})
                .groupby("label")["has_path_or_query"].mean().round(3).reset_index())
    by_source = (train.assign(has_path_or_query=has_path)
                 .groupby(["sources", "label"])["has_path_or_query"].agg(["mean", "size"]).round(3)
                 .reset_index().sort_values("size", ascending=False).head(8))

    lines += [
        "## Gini gain and information gain of the best single split", "",
        "Each value is how much one threshold on that feature alone reduces impurity at the "
        "root of a tree. Higher means the feature separates the classes better on its own.", "",
        md_table(rank.round(4)), "",
        "![ranking](figures/feature_ranking.png)", "",
        "![distributions](figures/feature_distributions.png)", "",
        "## Redundancy and correlation", "",
        "Feature pairs with |Pearson r| >= 0.8 carry largely the same information. A decision tree "
        "copes with this, but redundant pairs split the importance between them, which makes the "
        "importance ranking harder to read.", "",
        md_table(pairs) if len(pairs) else "No pair reaches |r| >= 0.8.", "",
        "![correlation](figures/correlation_heatmap.png)", "",
        "## Shortcut check: share of URLs with a path or query", "",
        "Tranco and URL-Phish list legitimate sites as bare domains or homepages, while the "
        "Kaggle and Common Crawl URLs are mostly deep links. If legitimate URLs rarely had a "
        "path, a tree could learn 'has a path means phishing', which fails on real traffic. "
        "The final training set samples legitimate URLs so the two classes have a path equally "
        "often. The host-only model in the results report checks how much performance depends "
        "on the path.", "",
        md_table(shortcut), "",
        md_table(by_source), "",
        "Per-feature means and medians by class are in reports/feature_summary.csv.", ""]
    (REPORTS / "analysis_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(rank.head(10).to_string(index=False))
    print(pairs.to_string(index=False) if len(pairs) else "no redundant pairs")


if __name__ == "__main__":
    main()
