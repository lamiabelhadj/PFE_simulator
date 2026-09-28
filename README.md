# IoT Authentication Flow Simulator

A simulation framework for IoT authentication flows that generates labelled
synthetic datasets for anomaly-detection model training.

The simulator models the authentication lifecycle as a **finite state machine**,
drives it through a three-layer **Scenario → Event → Output** engine pipeline,
and injects **nine categories of authentication anomalies** by forcing invalid
state transitions. It ships with a scikit-learn ML pipeline and a Streamlit UI
for generating, exploring and benchmarking the data.

---

## Table of contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Authentication lifecycle](#authentication-lifecycle)
- [Security stack](#security-stack)
- [Anomaly model](#anomaly-model)
- [Dataset](#dataset)
- [ML pipeline](#ml-pipeline)
- [Project structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Roadmap](#roadmap)
- [Authors](#authors)

---

## Overview

Real IoT datasets are scarce, rarely focused on authentication events, and
difficult to adapt to controlled attack scenarios. This project addresses that
gap by:

1. **Modelling** the IoT authentication lifecycle as a state machine with
   22 event types, 18 states and 43 valid transitions across a
   **Device → Edge → Cloud** architecture.
2. **Injecting** adversarial behaviour — 9 anomaly families such as token
   replay, nonce reuse, impersonation and unauthorized access — by forcing the
   state machine into an invalid transition at a precise point in the flow.
3. **Exporting** three complementary, fully-labelled views of every run
   (nested JSON event log, per-event CSV, and a per-session feature CSV with
   **103 columns**) ready to train and benchmark anomaly-detection ML models.

The domain model (`simulator/core/`) uses real cryptographic primitives —
ECDH on secp256r1, Blake2s hashing, OAuth2/ACE-style tokens, and an MQTT v5
broker model — while the engine pipeline (`simulator/engines/`) synthesises the
protocol-level event sequences and per-session features that make up the
dataset.

---

## Architecture

### Conceptual layers (`simulator/core/`)

```
┌────────────────────────────────────────────────────────────────────────┐
│  Device layer      IoT endpoints: sensor · actuator · gateway_client     │
│                    identity, ECDH keypair, PSK, battery, trust score      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                    │  ECDH-secured channel
┌──────────────────────────────────┴─────────────────────────────────────┐
│  Edge layer        Gateway (trusted enforcement point)                    │
│                    • Access control & sliding-window rate limiting        │
│                    • Replay-window tracking (Blake2s token hashing)        │
│                    • Zero-Trust continuous verification                    │
└──────────────┬──────────────────────────────────────┬───────────────────┘
               │                                        │
┌──────────────┴──────────────┐        ┌───────────────┴──────────────────┐
│  AuthServer                  │        │  MQTT Broker                       │
│  • PSK enrollment            │        │  • Token-gated CONNECT             │
│  • OAuth2/ACE token issuance │        │  • Topic-scope enforcement         │
│  • Token revalidation        │        │  • Pub/Sub session tracking        │
└──────────────────────────────┘        └────────────────────────────────────┘
```

The gateway is treated as **trusted** and is the single enforcement point
between untrusted devices and the cloud services.

### Generation pipeline (`simulator/engines/`)

The dataset is produced by a three-layer pipeline, one instance per session:

```
ScenarioEngine   →   defines WHAT to simulate
  produces a declarative ScenarioSpec: the normal step sequence plus, for
  anomalies, the invalid transition to inject and where to inject it.

EventEngine      →   defines HOW it plays out
  walks the ScenarioSpec through the StateMachine, sampling realistic delays,
  propagating token_id / nonce / session_id, and (for anomalies) forcing the
  invalid transition. Emits a correlated List[AuthEvent] + a SessionContext.

TemporalEngine   →   time-dependent logic
  per-session token/nonce lifetimes, exponential-backoff retry delays and
  replay-window checks that the EventEngine delegates to.

OutputViews      →   defines the OUTPUT
  renders the sequences into three formats (JSON log, event CSV, feature CSV).
```

Every generated event sequence is guaranteed to satisfy three properties:
**temporal** (monotonically increasing timestamps with per-event delays),
**state** (transitions taken directly from the state machine), and
**consistency** (`session_id` / `token_id` / `nonce` correlated across events).

---

## Authentication lifecycle

The canonical normal flow is a 14-event sequence driven through the state
machine. Two benign variants add realism: a **retry** flow (one auth failure
followed by a successful retry) and a **renewal** flow (mid-session token
renewal).

| Phase | Events | Resulting state |
|-------|--------|-----------------|
| **Registration** | `registration_request`, `registration_confirmed` | `REGISTERED` |
| **Authentication** | `authentication_request`, `challenge_sent`, `nonce_received`, `response_sent`, `authentication_success` / `authentication_failure` | `AUTHENTICATED` / `AUTH_FAILED` |
| **Token issuance** | `token_issued`, `token_presented`, `token_validated`, `token_rejected` | `TOKEN_VALIDATED` |
| **Session** | `session_opened`, `session_closed` | `SESSION_OPEN` |
| **Resource access** | `access_request`, `access_granted`, `access_denied` | `ACCESS_GRANTED` |
| **Renewal / expiry** | `renewal_request`, `token_expired` | `RENEWAL_REQUESTED` / `TOKEN_EXPIRED` |
| **Control** | `retry`, `timeout`, `disconnect` | — |

The transition table encodes only valid lifecycle transitions; **any
`(state, event)` pair absent from it is a candidate anomaly**. After three
consecutive `AUTH_FAILED` outcomes, the machine auto-transitions to `BLOCKED`
(gateway rate-limiting a device after repeated failures).

---

## Security stack

| Component | Technology |
|-----------|------------|
| Key exchange | ECDH — secp256r1 curve (`Device` / `Gateway`) |
| Hashing | Blake2s (PSK hash, token fingerprinting, nonce & payload hashing) |
| Token protocol | OAuth2 / ACE (Authentication and Authorisation for Constrained Environments) — configurable lifetime, default 300 s |
| Access control | Topic-scope enforcement on MQTT topics |
| Security model | Zero Trust — continuous verification, trust scoring, least privilege |
| Transport model | MQTT v5 semantics (CONNECT / CONNACK / PUBLISH, QoS, topics) |

---

## Anomaly model

The attacker is treated as **non-invasive**: all anomalies are injected over
the protocol with no physical access to devices. Each anomaly forces the state
machine into an invalid transition at a chosen point in the flow, and is
labelled with its type, injection phase and severity.

| # | Anomaly | Severity | Injection point (`attack_phase`) | Key dataset signals |
|---|---------|----------|----------------------------------|---------------------|
| 1 | **replay_token** | medium | `token_presented` | `replay_window_violation`, `token_age_at_replay`, `credential_status` |
| 2 | **nonce_reuse** | medium | `nonce_received` | `n_nonce_reuses`, `nonce_age_at_reuse` |
| 3 | **timestamp_inconsistency** | medium | `response_sent` | `timestamp_delta_s` |
| 4 | **duplicate_sequence** | medium | `registration_request` (in open session) | `duplicate_session_count` |
| 5 | **impersonation** | high | `session_opened` | `identity_claim_mismatch`, `source_ip_change`, `credential_status` |
| 6 | **identity_token_mismatch** | high | `session_opened` | `token_device_mismatch`, `identity_claim_mismatch` |
| 7 | **access_without_auth** | high | `access_request` | `unauthorized_access_attempt`, `steps_before_access` |
| 8 | **abnormal_failure_rate** | high | `authentication_request` (from `BLOCKED`) | `failed_auth_count`, `n_failures` |
| 9 | **abnormal_renewal** | medium | `renewal_request` | `n_renewal_request`, `re_auth_required` |

Severity values are `none` / `medium` / `high`. The per-anomaly share of the
attack pool is set by `attack_distribution` (must sum to 1.0).

---

## Dataset

Every run writes three files to `simulator/data/output/` (plus an optional
Parquet copy of the feature table). For an output name of
`iot_auth_dataset.csv` the stem is `iot_auth_dataset`:

| File | Granularity | Shape |
|------|-------------|-------|
| `<stem>_events.json` | one object per session, full nested event detail | — |
| `<stem>_event_log.csv` | one row per `AuthEvent` | 26 columns |
| `<stem>_features.csv` | one row per session (ML feature table) | 103 columns |

### Default output

| Property | Value |
|----------|-------|
| Sessions | 1,100 (configurable) |
| Normal sessions | 1,000 (~91%) — 65% pure, 20% retry, 15% renewal |
| Attack sessions | 100 (~9%) — split across the 9 anomaly types |
| Device pool | 200 devices across 5 gateways |
| Output format | CSV + JSON (optional Parquet) |
| Location | `simulator/data/output/` |

### Feature-table column groups (103 total)

| Group | Cols | Examples |
|-------|------|----------|
| Identifiers | 4 | `scenario_id`, `session_id`, `device_id`, `gateway_id` |
| Identity & discovery | 5 | `claimed_device_id`, `source_ip`, `registered_device`, `battery_level`, … |
| Network & pairing | 9 | `tcp_flags`, `tcp_rtt`, `packet_rate`, `pairing_latency_ms`, … |
| Enrollment & auth | 11 | `credential`/`connack_code`, `auth_result`, `failed_auth_count`, `keep_alive`, … |
| Authorization | 6 | `requested_topic`, `operation`, `topic_scope_violation`, `retain_flag`, … |
| MQTT session | 7 | `message_rate`, `byte_rate`, `payload_length`, `payload_hash`, `qos_level`, … |
| Continuous re-auth / Zero Trust | 5 | `trust_score`, `re_auth_required`, `source_ip_change`, `replay_window_violation`, … |
| Step latencies | 6 | `s1_latency_ms` … `s6_latency_ms` |
| Temporal aggregates | 4 | `session_duration_s`, `mean_delay_s`, `max_delay_s`, `min_delay_s` |
| Event-type counts | 23 | `n_events`, `n_token_issued`, `n_authentication_failure`, … |
| State coverage | 4 | `visited_states`, `reached_session_open`, `reached_authenticated`, … |
| Failure signals | 3 | `n_failures`, `n_retries`, `failure_rate` |
| Token / identity signals | 4 | `n_token_reuses`, `n_nonce_reuses`, `identity_mismatch`, `n_state_jumps` |
| Per-anomaly signals | 8 | `token_age_at_replay`, `timestamp_delta_s`, `token_device_mismatch`, … |
| **Labels** | 4 | `is_anomaly`, `attack_type`, `attack_phase`, `severity` |

### Label schema

| Column | Values |
|--------|--------|
| `is_anomaly` | `0` normal · `1` anomaly |
| `attack_type` | `normal` · one of the 9 anomaly labels |
| `attack_phase` | `none` · the event type at which the anomaly was injected |
| `severity` | `none` · `medium` · `high` |

---

## ML pipeline

`ml/` provides an end-to-end scikit-learn pipeline that can generate a fresh
dataset (or consume a pre-generated feature DataFrame), preprocess it, and
train and benchmark three classifiers.

- **Models** — Logistic Regression, Decision Tree, Random Forest (thin
  sklearn wrappers with a common `fit / predict / predict_proba / classes_`
  interface).
- **Preprocessing** (`ml/preprocessing.py`) — ordinal-encodes low-cardinality
  categoricals, standard-scales numerics, and does a stratified train/test
  split. It **drops label-leaking columns** (`attack_type` / `attack_phase` /
  `severity` for the binary target; `is_anomaly` / `attack_phase` / `severity`
  for the multiclass target) and high-cardinality identifiers.
- **Targets** — `is_anomaly` (binary) or `attack_type` (multiclass).
- **Evaluator** (`ml/evaluator.py`) — Accuracy, Precision, Recall, F1
  (weighted), ROC-AUC, confusion matrix, per-class report and top feature
  importances, plus a sorted model-comparison table saved to CSV.

### Common evaluation pipeline (`ml/evaluation/`)

One shared implementation of the load → clean → split → evaluate → compare
steps, so every model is scored on the same rows, columns and metrics. It
works with any scikit-learn classifier (`Pipeline`, `GridSearchCV`, …).

| Module | Provides |
|--------|----------|
| `data.py` | `load_features()`, `prepare()` → `Dataset`, `.split()` → `Split`, `structural_leak_columns()` |
| `estimators.py` | `make_preprocessor()` (scaled or passthrough + one-hot), `default_models()` |
| `metrics.py` | anomaly-class (binary) / macro (multiclass) metrics, per-attack-type table, operating points |
| `report.py` | `evaluate()` → `EvalReport`, `compare()`, `benchmark()`, `cross_validate()`, `leakage_check()`, `feature_importance()` |
| `plots.py` | confusion matrix, ROC/PR overlay, per-attack recall, threshold curves, comparison bars, importances |

```python
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from ml.evaluation import load_features, prepare, make_preprocessor, evaluate, leakage_check
from ml.evaluation import plots

data  = prepare(load_features(), target="is_anomaly")   # or "attack_type"
split = data.split(test_size=0.20, seed=42)

def rf(d):   # a factory, so leakage_check can rebuild it on fewer columns
    return Pipeline([("pre", make_preprocessor(d)),
                     ("rf",  RandomForestClassifier(n_estimators=300, random_state=42))])

report = evaluate(rf(split), split, name="Random Forest", oof_cv=5)
report.print()                 # metrics, classification report, confusion matrix
report.per_attack_type()       # detection rate per attack type
report.operating_points()      # thresholds tuned on out-of-fold TRAIN scores
plots.plot_binary_panel(report)
leakage_check(rf, data)        # all features vs structure-free, same test rows
```

From the command line (writes CSVs, `run.json` and PNGs to
`simulator/data/output/evaluation/<target>/`):

```bash
python -m ml.evaluation --target both --leakage-check --cv 5
python -m ml.evaluation --models rf --structure-free --no-plots
```

Binary precision / recall / F1 are for the **anomaly class**, not weighted
averages. A weighted F1 is carried by the normal majority and hides missed
attacks. `ml/evaluator.py` (used by `ml/pipeline.run()`) still reports weighted
metrics.

> **Note on label leakage:** because injected anomalies terminate the session
> at the injection point, attack sessions are systematically shorter than
> normal ones and several structural features correlate strongly with the
> label. Treat very high scores with caution and prefer the leakage-aware
> preprocessing when benchmarking.

---

## Project structure

```
PFE_simulator/
├── README.md
├── pipeline/
│   └── requirements.txt                # Python dependencies
└── IoT_auth_simulator/                 # run commands from here
    ├── main.py                         # CLI entry point
    ├── simulator/
    │   ├── event_model.py              # EventType, AuthState, EventResult, AuthEvent
    │   ├── state_machine.py            # transition table + anomaly transitions
    │   ├── runner.py                   # session orchestrator
    │   ├── config/
    │   │   └── settings.py             # all parameters (dataclasses) + cfg singleton
    │   ├── core/
    │   │   ├── device.py               # IoT device — identity, ECDH, trust score
    │   │   ├── gateway.py              # edge gateway — access control, replay window
    │   │   └── auth_server.py          # AuthServer (enrollment, tokens) + MQTTBroker
    │   ├── engines/
    │   │   ├── scenario_engine.py      # Layer 1 — ScenarioSpec factory
    │   │   ├── event_engine.py         # Layer 2 — events + SessionContext
    │   │   └── temporal_engine.py      # token/nonce/retry temporal logic
    │   ├── data/
    │   │   ├── output_views.py         # JSON / event CSV / feature CSV renderers
    │   │   └── exporter.py             # thin save() wrapper used by CLI + UI
    │   └── UI/
    │       └── ui_app.py               # Streamlit dashboard
    └── ml/
        ├── pipeline.py                 # generate → preprocess → train → evaluate
        ├── preprocessing.py            # leakage-aware feature preprocessing
        ├── evaluator.py                # metrics + model comparison
        ├── evaluation/                 # common evaluation pipeline (python -m ml.evaluation)
        │   ├── data.py                 # load, clean, stratified split
        │   ├── estimators.py           # shared preprocessor + reference models
        │   ├── metrics.py              # metric functions and breakdown tables
        │   ├── report.py               # evaluate / compare / leakage_check / CV
        │   └── plots.py                # matplotlib figures
        └── models/
            ├── logistic_regression.py
            ├── decision_tree.py
            └── random_forest.py
```

---

## Installation

**Requirements:** Python 3.11 or later.

```bash
# 1. Clone the repository
git clone https://github.com/your-username/iot-auth-simulator.git
cd iot-auth-simulator/PFE_simulator

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r pipeline/requirements.txt
```

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `numpy` | ≥ 1.26 | Numerical sampling |
| `pandas` | ≥ 2.2 | DataFrame construction and export |
| `scipy` | ≥ 1.13 | Numerical support |
| `cryptography` | ≥ 42.0 | ECDH key exchange, Blake2s hashing |
| `scikit-learn` | ≥ 1.4 | ML pipeline (preprocessing, models, metrics) |
| `matplotlib` | ≥ 3.8 | Charts |
| `seaborn` | ≥ 0.13 | Correlation heatmap |
| `streamlit` | (UI) | Web dashboard |
| `pyarrow` | ≥ 16.0 | Optional Parquet export |
| `tqdm`, `pyyaml`, `python-dotenv`, `jupyterlab` | — | Utilities / notebooks |

> `streamlit` is required for the UI — install it (`pip install streamlit`) if
> you plan to run the dashboard.

---

## Usage

All commands are run from the `IoT_auth_simulator/` directory.

### Command-line interface

```bash
# Default run (1000 normal, 100 attack, 200 devices, seed 42)
python main.py

# Custom run
python main.py --normal 2000 --attack 500 --devices 300 --seed 7

# Also export a Parquet copy of the feature table
python main.py --normal 1000 --attack 250 --parquet --out my_dataset.csv
```

**CLI options**

| Flag | Default | Description |
|------|---------|-------------|
| `--normal` | 1000 | Number of normal sessions |
| `--attack` | 100 | Number of attack sessions |
| `--devices` | 200 | Device pool size |
| `--seed` | 42 | Random seed for reproducibility |
| `--out` | `iot_auth_dataset.csv` | Output filename (defines the file stem) |
| `--parquet` | off | Also export a Parquet copy of the feature table |

### Streamlit UI

```bash
streamlit run simulator/UI/ui_app.py
```

Opens a browser dashboard where you can:

- Configure session counts and per-anomaly attack distribution with sliders
- Run the simulation with a live progress bar
- Explore both the feature table and the event log with charts, a filterable
  table, descriptive statistics and a correlation heatmap
- Download the feature CSV and event-log CSV directly from the browser

### Programmatic use

```python
from simulator.runner import run_simulation
from simulator.data.exporter import save
from simulator.config.settings import cfg

cfg.simulation.num_sessions_normal = 500
cfg.simulation.num_sessions_attack = 100
cfg.simulation.random_seed         = 0

sequences = run_simulation()                     # List[(events, SessionContext)]
feature_csv = save(sequences, filename="my_dataset.csv", parquet=False)
```

### ML pipeline

```python
from ml.pipeline import run

# Generate a fresh dataset, then train & benchmark all three models (binary)
results = run(n_normal=800, n_attack=200, target="is_anomaly")

# Or run on a pre-generated feature CSV, multiclass target
import pandas as pd
df = pd.read_csv("simulator/data/output/iot_auth_dataset_features.csv")
results = run(df=df, target="attack_type")
```

---

## Configuration

All parameters are defined as typed dataclasses in
`simulator/config/settings.py`. Import the singleton `cfg` anywhere:

```python
from simulator.config.settings import cfg
```

| Dataclass | Key parameters |
|-----------|----------------|
| `SimulationConfig` | `num_devices`, `num_gateways`, `num_sessions_normal`, `num_sessions_attack`, `attack_distribution`, `random_seed`, `output_filename` |
| `NetworkConfig` | subnets, latency / RTT / packet-rate Gaussian parameters for normal and attack traffic |
| `DeviceConfig` | battery range, PSK length, device types, firmware versions, MQTT keep-alive values |
| `SecurityConfig` | ECDH curve, token lifetime, replay window, trust-score thresholds, max failed auth |
| `MQTTConfig` | MQTT version, QoS levels, payload-size range, session-duration range, message-rate profiles |
| `AttackConfig` | per-anomaly fine-tuning, DoS burst parameters, severity mapping |
| `MLConfig` | train/test/validation split, model hyperparameters, columns to drop before training |

---

## Roadmap

- [x] ML pipeline — preprocessing, Logistic Regression, Decision Tree, Random
  Forest, evaluator (Accuracy, Precision, Recall, F1, ROC-AUC)
- [ ] Address label leakage — lengthen attack sessions past the injection point
  so structural features stop separating the classes trivially
- [ ] Additional anomaly types — MITM, Sybil, On-Off, Downgrade/Rollback
- [ ] Device behavioural profiles — per-type traffic patterns
  (camera vs sensor vs actuator)
- [ ] Wire the `core/` domain components (Gateway, AuthServer, MQTTBroker) into
  the generation path so ECDH / token issuance is exercised end-to-end
- [ ] Multi-gateway topology — multiple gateways with separate device pools
- [ ] Unit tests — pytest suite covering each state transition and anomaly
- [ ] YAML config override — `python main.py --config experiment.yaml`

---

## Authors

**Lamia Belhadj Sghaier**
Sorbonne Paris Nord University — L2TI Laboratory — 2026
