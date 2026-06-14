"""
ml/pipeline.py
───────────────
End-to-end ML pipeline: generate dataset → preprocess → train → evaluate.

Usage
─────
    # Programmatic
    from ml.pipeline import run
    results = run(n_normal=800, n_attack=200, target="is_anomaly")

    # From a pre-generated DataFrame
    import pandas as pd
    df = pd.read_csv("data/output/iot_auth_features.csv")
    results = run(df=df, target="attack_type")
"""

import time
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from ml.preprocessing import Preprocessor
from ml.evaluator import EvalResult, compare_models, evaluate, print_report
from ml.models.logistic_regression import LogisticRegressionModel
from ml.models.decision_tree import DecisionTreeModel
from ml.models.random_forest import RandomForestModel


# ── Default model set ─────────────────────────────────────────────────────────
_ALL_MODELS = {
    "logistic_regression": LogisticRegressionModel,
    "decision_tree":       DecisionTreeModel,
    "random_forest":       RandomForestModel,
}

# ── Default attack distribution for fresh generation ─────────────────────────
_DEFAULT_DIST = {
    "replay_token":            0.12,
    "nonce_reuse":             0.12,
    "timestamp_inconsistency": 0.12,
    "duplicate_sequence":      0.12,
    "impersonation":           0.13,
    "identity_token_mismatch": 0.13,
    "access_without_auth":     0.13,
    "abnormal_failure_rate":   0.07,
    "abnormal_renewal":        0.06,
}


def _generate_dataset(
    n_normal: int,
    n_attack: int,
    seed:     int,
    dist:     Dict[str, float],
) -> pd.DataFrame:
    """Generate a fresh labelled dataset using the simulation pipeline."""
    import time as _time
    from simulator.engines.scenario_engine import ScenarioEngine
    from simulator.engines.event_engine import EventEngine
    from simulator.data.output_views import to_feature_df

    print(f"  Generating {n_normal} normal + {n_attack} attack sessions …")
    t0  = _time.perf_counter()
    eng = ScenarioEngine(seed=seed)
    ee  = EventEngine(
        device_id      = "dev-sim",
        gateway_id     = "gw-sim",
        auth_server_id = "as-sim",
        start_time     = _time.time(),
    )
    specs = eng.batch(
        n_normal=n_normal,
        n_attack=n_attack,
        distribution=dist,
    )
    pairs = [ee.execute(s) for s in specs]
    df    = to_feature_df(pairs)
    print(f"  Generated {len(df)} rows x {len(df.columns)} cols in {_time.perf_counter()-t0:.1f}s")
    return df


def run(
    df:           Optional[pd.DataFrame] = None,
    n_normal:     int  = 800,
    n_attack:     int  = 200,
    target:       str  = "is_anomaly",
    seed:         int  = 42,
    model_names:  Optional[List[str]] = None,
    verbose:      bool = True,
    save_results: bool = True,
    output_dir:   str  = "data/output",
    dist:         Optional[Dict[str, float]] = None,
) -> Dict[str, EvalResult]:
    """
    End-to-end ML pipeline.

    Parameters
    ----------
    df           : pre-generated feature DataFrame; if None, one is generated
    n_normal     : normal sessions to generate (ignored when df is provided)
    n_attack     : attack sessions to generate (ignored when df is provided)
    target       : "is_anomaly" (binary) or "attack_type" (multiclass)
    seed         : random seed for generation and model training
    model_names  : list of model keys to run; default = all three
    verbose      : print progress and per-model reports
    save_results : write comparison CSV to output_dir
    output_dir   : where to save results CSV
    dist         : attack type distribution dict (must sum to 1.0)

    Returns
    -------
    Dict[model_name → EvalResult]
    """
    sep = "=" * 55

    if verbose:
        print(f"\n{sep}")
        print(f"  IoT Auth Simulator — ML Pipeline")
        print(f"  Target  : {target}")
        print(sep)

    # ── Dataset ───────────────────────────────────────────────────────────────
    if df is None:
        dist = dist or _DEFAULT_DIST
        df   = _generate_dataset(n_normal, n_attack, seed, dist)
    else:
        if verbose:
            print(f"  Using provided DataFrame: {len(df)} rows x {len(df.columns)} cols")

    # ── Preprocessing ─────────────────────────────────────────────────────────
    if verbose:
        print(f"\n  Preprocessing …")
    pre = Preprocessor(target=target, random_state=seed)
    X_train, X_test, y_train, y_test = pre.fit_transform(df)

    if verbose:
        print(f"  Features : {len(pre.feature_names_)}")
        print(f"  Train    : {len(y_train)}  |  Test: {len(y_test)}")
        print(f"  Train class distribution:")
        for cls, cnt in pre.class_distribution(y_train).items():
            print(f"    {str(cls):<30} {cnt}")

    # ── Train & evaluate ──────────────────────────────────────────────────────
    model_names = model_names or list(_ALL_MODELS.keys())
    results: Dict[str, EvalResult] = {}

    for key in model_names:
        if key not in _ALL_MODELS:
            print(f"  [skip] Unknown model '{key}'")
            continue

        model = _ALL_MODELS[key](random_state=seed)
        if verbose:
            print(f"\n  Training {model.name} …")

        result = evaluate(
            model         = model,
            X_train       = X_train,
            y_train       = y_train,
            X_test        = X_test,
            y_test        = y_test,
            feature_names = pre.feature_names_,
        )
        results[key] = result

        if verbose:
            print_report(result)

    # ── Comparison table ──────────────────────────────────────────────────────
    if results:
        cmp_df = compare_models(list(results.values()))
        if verbose:
            print(f"\n{sep}")
            print("  Model Comparison (sorted by F1)")
            print(sep)
            print(cmp_df.to_string())
            print(sep)

        if save_results:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"ml_results_{target}.csv"
            cmp_df.to_csv(path)
            if verbose:
                print(f"\n  Results saved -> {path}")

    return results
