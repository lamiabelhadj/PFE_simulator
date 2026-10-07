"""Run the pipeline twice into fresh directories and compare every output by sha256.

    python verify_reproducibility.py            # uses a temp dir, removed afterwards
    python verify_reproducibility.py --keep     # keep both runs for inspection

Exit code 0 = every file identical across runs.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run_once(out: Path, input_json: str | None) -> dict:
    cmd = [sys.executable, str(HERE / "run_pipeline.py"), "--out", str(out)]
    if input_json:
        cmd += ["--input", input_json]
    subprocess.run(cmd, check=True)
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=None)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    root = Path(tempfile.mkdtemp(prefix="auth_eda_repro_"))
    try:
        a = run_once(root / "run_a", args.input)
        b = run_once(root / "run_b", args.input)
        files = sorted(set(a["outputs"]) | set(b["outputs"]))
        diff = [f for f in files if a["outputs"].get(f) != b["outputs"].get(f)]
        print(f"\ninput sha256 identical: {a['input']['sha256'] == b['input']['sha256']}")
        print(f"compared {len(files)} output files: {len(files) - len(diff)} identical, {len(diff)} different")
        for f in diff:
            print(f"  DIFFERENT: {f}")
        return 1 if diff else 0
    finally:
        if args.keep:
            print(f"runs kept in {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
