"""
ml/evaluation
──────────────
Common evaluation pipeline shared by every model notebook and the CLI:

    load_features → prepare → split → (model factory) → evaluate → compare
                                                     ↳ leakage_check / cross_validate

Usage
─────
    from ml.evaluation import (load_features, prepare, make_preprocessor,
                               evaluate, compare, leakage_check)
    from ml.evaluation import plots

    data  = prepare(load_features(), target="is_anomaly")
    split = data.split(test_size=0.20, seed=42)

    def rf(d):
        return Pipeline([("pre", make_preprocessor(d)),
                         ("rf",  RandomForestClassifier(n_estimators=300))])

    report = evaluate(rf(split), split, name="Random Forest", oof_cv=5)
    report.print()
    report.per_attack_type()
    report.operating_points()
    plots.plot_binary_panel(report)
    leakage_check(rf, data)

CLI:  python -m ml.evaluation --help
Plots live in ml.evaluation.plots (imported separately, so matplotlib stays optional).
"""

from ml.evaluation.data import (
    Dataset,
    Split,
    class_balance,
    find_features_csv,
    load_features,
    prepare,
    structural_leak_columns,
)
from ml.evaluation.estimators import default_models, make_preprocessor
from ml.evaluation.metrics import (
    attack_type_table,
    binary_metrics,
    multiclass_metrics,
    operating_points,
)
from ml.evaluation.report import (
    EvalReport,
    benchmark,
    compare,
    cross_validate,
    evaluate,
    feature_importance,
    leakage_check,
)

__all__ = [
    "Dataset", "Split", "class_balance", "find_features_csv", "load_features",
    "prepare", "structural_leak_columns",
    "default_models", "make_preprocessor",
    "attack_type_table", "binary_metrics", "multiclass_metrics", "operating_points",
    "EvalReport", "benchmark", "compare", "cross_validate", "evaluate",
    "feature_importance", "leakage_check",
]
