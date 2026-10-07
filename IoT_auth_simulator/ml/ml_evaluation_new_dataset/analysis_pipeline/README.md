# Analysis pipeline: `scientific-candidate.json`

A reproducible pipeline that converts the IoT authentication scientific candidate
from nested JSON to tidy CSV, validates it, and analyses it end to end. It
writes a narrative report (`outputs/report.html`, self-contained, and `outputs/report.md`).

## Run

```bash
pip install -r requirements.txt
python run_pipeline.py                     # default: ../scientific-candidate.json → outputs/
python run_pipeline.py --input other.json --out other_outputs/
python verify_reproducibility.py           # runs twice, compares sha256 of every output
```

A full run takes about 5 minutes. Most of that is 5×5 device-grouped cross-validation.
The exit code is non-zero if any integrity check FAILs.

## Stages

| # | module | what it does | main outputs |
|---|---|---|---|
| 1 | `auth_eda/convert.py` | JSON → CSV: keeps the detector view (events) separate from privileged metadata | `data/events.csv`, `data/samples.csv` |
| 2 | `auth_eda/validate.py` | 26 integrity checks: contract, event consistency, protocol grammar, metadata ↔ observations | `tables/validation_checks.csv` |
| 3 | `auth_eda/features.py` | per-session features from events **only**, each with a group and description | `data/features.csv`, `tables/feature_dictionary.csv` |
| 4 | `auth_eda/eda.py` | composition, design balance, session anatomy, grammar, timing, nonces, tokens, devices, latent profiles, correlations | `tables/*.csv`, `figures/01–11` |
| 5 | `auth_eda/separability.py` | univariate AUC/MI (4 comparisons), transparent rule detectors, metadata leakage audit | `tables/univariate_*`, `rule_*`, `metadata_leakage_audit.csv`, `figures/12` |
| 6 | `auth_eda/models.py` | LR / RF / depth-3 tree, StratifiedGroupKFold by device, 3 feature sets (all, mechanism-only, context-only) | `tables/cv_*`, `figures/13–14` |
| 7 | `auth_eda/report.py` | narrative report; every number comes from the stages above | `report.md`, `report.html` |
| – | `run_pipeline.py` | orchestration + `manifest.json` (input hash, seed, versions, sha256 of each output) | `manifest.json` |

Stages 2–7 read the CSVs written in stage 1, not the JSON, so the CSVs are the
single source of truth.

## Reproducibility guarantees

- One seed (`auth_eda/config.py: SEED`) drives every random step.
- Fixed orderings for roles and event types; CSVs written with `\n` line endings.
- PNGs saved without software or timestamp metadata.
- `manifest.json` records hashes; `verify_reproducibility.py` checks that two runs are byte-identical.
- Pinned library versions in `requirements.txt`. Other versions should give the same numbers, but bytes may differ.

## Using the CSVs for modelling

- Features: `data/features.csv`, minus `sample_key, device, y, role, role_kind, semantic_family`.
- Target: `y` (1 = anomaly). Per-role evaluation: `role`.
- Split by `device` (GroupKFold). Sessions from one device share a latent profile.
- Never use `data/samples.csv` columns as features. Several of them encode the label (see the leakage audit).
