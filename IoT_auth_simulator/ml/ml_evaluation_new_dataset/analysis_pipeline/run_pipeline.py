"""Run the full analysis pipeline end to end.

    python run_pipeline.py                         # default input / outputs/
    python run_pipeline.py --input X.json --out D  # any candidate, any folder

Stages: convert → validate → features → eda → separability → models →
report → manifest. Each stage reads the CSVs written by stage 1, so the CSVs
are the single source of truth for everything downstream.
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from auth_eda import convert, eda, features, models, report, separability, validate  # noqa: E402
from auth_eda.config import DEFAULT_INPUT, DEFAULT_OUTPUT, SEED, Paths  # noqa: E402


def _versions() -> dict:
    import matplotlib, pandas, scipy, sklearn  # noqa: E401
    return {"python": platform.python_version(), "numpy": np.__version__, "pandas": pandas.__version__,
            "scipy": scipy.__version__, "scikit-learn": sklearn.__version__, "matplotlib": matplotlib.__version__}


def write_manifest(paths: Paths, conv: dict) -> dict:
    files = sorted(p for p in paths.out.rglob("*") if p.is_file() and p.name != "manifest.json")
    manifest = {
        "input": {"path": paths.input_json.name, "sha256": conv["input_sha256"], "bytes": conv["input_bytes"],
                  **conv["header"]},
        "seed": SEED,
        "environment": _versions(),
        "outputs": {p.relative_to(paths.out).as_posix(): convert.sha256_file(p) for p in files},
    }
    (paths.out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252

    random.seed(SEED)
    np.random.seed(SEED)
    paths = Paths(args.input.resolve(), args.out.resolve())
    paths.make()

    def step(name):
        print(f"[{time.strftime('%H:%M:%S')}] {name}", flush=True)

    step("1/7 convert JSON → CSV")
    conv = convert.run(paths)
    events, samples = convert.reload(paths)

    step("2/7 validate")
    checks = validate.run(paths, conv["raw"], events, samples)
    print(checks["status"].value_counts().to_string())

    step("3/7 features")
    feats = features.run(paths, events, samples)
    num_cols = features.numeric_feature_names(feats)

    step("4/7 exploratory analysis")
    facts = {"header": conv["header"], "input_sha256": conv["input_sha256"], "checks": checks,
             "n_features": len(num_cols)}
    facts["eda"] = eda.run(paths, events, samples, feats, num_cols)

    step("5/7 separability & leakage")
    facts["sep"] = separability.run(paths, feats, samples, num_cols, features.FEATURE_INFO)

    step("6/7 baseline models (device-grouped CV)")
    facts["models"] = models.run(paths, feats, num_cols)

    step("7/7 report + manifest")
    facts["versions"] = _versions()
    report.build(paths, facts)
    write_manifest(paths, conv)
    print(f"done → {paths.out / 'report.html'}")
    return 1 if (checks["status"] == "FAIL").any() else 0


if __name__ == "__main__":
    raise SystemExit(main())
