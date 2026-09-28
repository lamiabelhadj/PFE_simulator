"""
ml/evaluation/__main__.py
──────────────────────────
Benchmark the reference models on the feature table and write every table and
figure to disk.

Usage (from IoT_auth_simulator/)
────────────────────────────────
    python -m ml.evaluation                                # binary, all 3 models
    python -m ml.evaluation --target attack_type
    python -m ml.evaluation --target both --leakage-check --cv 5
    python -m ml.evaluation --models rf --structure-free --no-plots

Outputs → simulator/data/output/evaluation/<target>[_structure_free]/
    comparison.csv                  one row per model (ranked)
    <model>_per_attack_type.csv     detection rate per attack type
    <model>_operating_points.csv    binary: default vs tuned thresholds
    <model>_confusion.csv
    cv_scores.csv                   --cv k: mean / std per metric per model
    leakage_check.csv               --leakage-check: all vs structure-free
    figures/*.png                   unless --no-plots
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from ml.evaluation.data import load_features, prepare
from ml.evaluation.estimators import default_models
from ml.evaluation.report import benchmark, compare, cross_validate, leakage_check

_DEFAULT_OUT = Path(__file__).resolve().parents[2] / "simulator" / "data" / "output" / "evaluation"


def _parse_args(argv=None) -> argparse.Namespace:
    models = default_models()
    ap = argparse.ArgumentParser(prog="python -m ml.evaluation", description=__doc__.split("\n\n")[0])
    ap.add_argument("--csv", help="feature CSV (default: auto-discover *_features.csv)")
    ap.add_argument("--target", choices=["is_anomaly", "attack_type", "both"], default="is_anomaly")
    ap.add_argument("--models", nargs="+", choices=list(models), default=list(models))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test-size", type=float, default=0.20)
    ap.add_argument("--structure-free", action="store_true",
                    help="drop the structural-leak features before training")
    ap.add_argument("--leakage-check", action="store_true",
                    help="also score every model with vs without structural features")
    ap.add_argument("--cv", type=int, default=0, help="k-fold CV spread per model (0 = off)")
    ap.add_argument("--oof-cv", type=int, default=5,
                    help="folds for honest threshold tuning on train (0 = tune on test, optimistic)")
    ap.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    ap.add_argument("--no-plots", action="store_true")
    return ap.parse_args(argv)


def _run_target(df: pd.DataFrame, target: str, args) -> pd.DataFrame:
    sep = "=" * 70
    data = prepare(df, target=target, structure_free=args.structure_free)
    out = args.out / (target + ("_structure_free" if args.structure_free else ""))
    out.mkdir(parents=True, exist_ok=True)

    print(f"\n{sep}\n  Target: {target}   features: {data.X.shape[1]} "
          f"({len(data.num_cols)} numeric, {len(data.cat_cols)} categorical)\n{sep}")

    models = {k: v for k, v in default_models(args.seed).items() if k in args.models}
    split, reports = benchmark(data, models, test_size=args.test_size, seed=args.seed,
                               oof_cv=args.oof_cv or None, verbose=True)

    for key, r in reports.items():
        r.print()
        r.per_attack_type().to_csv(out / f"{key}_per_attack_type.csv")
        r.confusion_matrix().to_csv(out / f"{key}_confusion.csv")
        if r.task == "binary":
            ops = r.operating_points()
            ops.to_csv(out / f"{key}_operating_points.csv")
            print(f"\n  Operating points — {r.name}\n{ops.round(4).to_string()}")

    cmp_df = compare(reports.values())
    cmp_df.to_csv(out / "comparison.csv")
    print(f"\n{sep}\n  Model comparison (ranked by {next(iter(reports.values())).headline})\n{sep}")
    print(cmp_df.round(4).T.to_string())

    if args.cv:
        cv_rows = {models[k][0]: cross_validate(models[k][1], data, cv=args.cv, seed=args.seed)
                   for k in models}
        cv_df = pd.concat(cv_rows, names=["model", "metric"])
        cv_df.to_csv(out / "cv_scores.csv")
        print(f"\n  {args.cv}-fold CV (mean ± std)\n{cv_df.round(4).to_string()}")

    if args.leakage_check and not args.structure_free:
        leak = pd.concat({models[k][0]: leakage_check(models[k][1], data, args.test_size, args.seed)
                          for k in models}, names=["model", "features"])
        leak.to_csv(out / "leakage_check.csv")
        headline = next(iter(reports.values())).headline
        cols = [c for c in (headline, "roc_auc", "roc_auc_ovr_macro", "n_features") if c in leak]
        print(f"\n  Leakage check — all vs structure-free features\n{leak[cols].round(4).to_string()}")

    if not args.no_plots:
        _save_figures(list(reports.items()), out / "figures")

    (out / "run.json").write_text(json.dumps({
        "source": df.attrs.get("source"), "target": target, "seed": args.seed,
        "test_size": args.test_size, "structure_free": args.structure_free,
        "oof_cv": args.oof_cv, "models": [r.name for r in reports.values()],
        "dropped_columns": data.dropped,
    }, indent=2))
    print(f"\n  Outputs -> {out}")
    return cmp_df


def _save_figures(items, fig_dir: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from ml.evaluation import plots

    fig_dir.mkdir(parents=True, exist_ok=True)

    def save(fig, name):
        fig.savefig(fig_dir / f"{name}.png", dpi=130, bbox_inches="tight")
        plt.close(fig)

    reports = [r for _, r in items]
    for key, r in items:
        save(plots.plot_confusion(r), f"{key}_confusion")
        save(plots.plot_per_attack_type(r), f"{key}_per_attack_type")
        if r.task == "binary":
            save(plots.plot_thresholds(r), f"{key}_thresholds")
    save(plots.plot_comparison(reports), "comparison")
    if reports[0].task == "binary":
        save(plots.plot_roc_pr(reports), "roc_pr")


def main(argv=None) -> None:
    args = _parse_args(argv)
    df = load_features(args.csv)
    print(f"Loaded {df.attrs['source']}  ({len(df)} rows x {len(df.columns)} cols)")
    targets = ["is_anomaly", "attack_type"] if args.target == "both" else [args.target]
    for t in targets:
        _run_target(df, t, args)


if __name__ == "__main__":
    main()
