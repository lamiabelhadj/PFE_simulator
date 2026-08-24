# Historical implementation baseline

## Status

This document describes the repository at `new-main@27135bf`, frozen as tag `baseline-pre-canonical-sync-27135bf`.

It is **pre-canonical-sync implementation evidence**. It records what the repository implemented; it is not scientific or methodological authority and must not be used to fill gaps in `02 — Authentication & Behavioral Model` or `03 — Simulator & Dataset Methodology`.

The `sync/v1-canonical` branch initially points to this exact commit, so subsequent synchronization work can be compared directly with the frozen baseline.

Phase-0 verification confirmed that the active branch still points exactly to `27135bf` when these governance files were proposed, and the tag resolves to the same baseline.

## Repository shape

- `IoT_auth_simulator/main.py`: CLI entry point.
- `IoT_auth_simulator/simulator/config/`: mutable dataclass configuration singleton.
- `IoT_auth_simulator/simulator/core/`: device, gateway, authentication server, MQTT broker, and optional entity driver.
- `IoT_auth_simulator/simulator/engines/`: scenario, event, and per-session temporal helpers.
- `IoT_auth_simulator/simulator/data/`: nested JSON, event table, session feature table, CSV, and optional Parquet output.
- `IoT_auth_simulator/simulator/UI/`: Streamlit UI.
- `IoT_auth_simulator/ml/`: preprocessing, Logistic Regression, Decision Tree, Random Forest, evaluation, and notebooks.
- `pipeline/requirements.txt`: unpinned lower-bound dependencies.
- No repository test suite or CI configuration.

## Historical execution path

The default path is:

```text
CLI/UI → global cfg → run_simulation
       → ScenarioEngine.batch
       → sequential per-session EventEngine.execute
       → per-session StateMachine + TemporalEngine
       → List[(List[AuthEvent], SessionContext)]
       → nested JSON + event CSV/DataFrame + session feature CSV/DataFrame
       → optional session feature Parquet
```

This implementation is a sequential scenario-based synthetic trace and session-feature generator. It has no global clock, event queue, actor concurrency, or discrete-event scheduling kernel.

An optional `wire_entities` path exercises ECDH, enrollment, token issuance, broker sessions, and topic authorization on shared domain objects. With limited exceptions such as the emitted token ID, those entity decisions do not control the synthesized trace or feature values.

## Historical behavioral representation

Verified baseline counts:

- 23 `AuthState` values;
- 10 `DeviceState` values;
- 28 `EventType` values;
- 53 transition-table entries;
- 9 named anomaly/scenario types.

These counts and definitions are non-canonical. The two state models are not synchronized during default generation. `REGISTERED` and registration events coexist as legacy residue with discovery, pairing, and enrollment concepts.

The default generated flow uses a per-session transition table, sampled delays, UUID session/scenario/token identifiers, and propagated token/nonce context. Normal variants include retry, renewal, partial sessions, variable access cycles, denial/retry, disconnect, and open-ended traces.

## Historical anomaly mechanism

Named anomaly scenarios select an invalid `(state, event)` pair, run a normal prefix, force the state machine to the selected predecessor, emit one labelled failure event, and sometimes resume the normal trace.

Historical types are:

- `replay_token`
- `nonce_reuse`
- `timestamp_inconsistency`
- `duplicate_sequence`
- `impersonation`
- `identity_token_mismatch`
- `access_without_auth`
- `abnormal_failure_rate`
- `abnormal_renewal`

The generator also includes per-type “stealth” probabilities that skip injection while retaining a session attack label, and a benign false-positive mechanism that adds suspicious fields to some normal sessions.

These names, invalid transitions, injected flags, and probabilities are historical implementation choices. They do not establish canonical anomaly semantics.

## Historical temporal capability

- A local floating-point session clock advances by sampled event delays.
- Retry events use exponential backoff with jitter.
- Token and nonce times are tracked per session.
- A timestamp anomaly may backdate one emitted event while leaving the internal clock advancing.
- Lifetime constants conflict across central configuration, `TemporalEngine`, and wired entities.
- Most lifetime/retry predicates do not gate scenario execution.
- Sessions execute sequentially and independently by default.

## Historical outputs and ground truth

The implementation can produce:

- in-memory event sequences plus session context;
- nested per-session JSON;
- one-row-per-event CSV/DataFrame;
- one-row-per-session feature CSV/DataFrame;
- optional session feature Parquet.

The current feature builder emits 109 columns. Session aggregation uses completed-trace information such as total duration, counts, reached states, failure rate, reuse counts, and state jumps.

Historical ground truth is distributed across:

- injected-event `anomaly_label`;
- session `attack_type`, `attack_phase`, and `severity`;
- derived `is_anomaly`;
- attack-specific signal fields.

There is no explicit injection-action record, forced-transition flag, source-event link for replayed material, or versioned run/config/schema manifest. Stealth scenarios can have an attack-labelled session context while their events and top-level JSON scenario type appear normal.

## Historical reproducibility and ML capability

- Python's global `random` generator is seeded.
- UUIDs, PSKs, wall-clock start times, and core entity timestamps are not seed-controlled.
- Run configuration, code version, schema version, and injection parameters are not persisted.
- ML targets are `is_anomaly` and `attack_type`.
- Models are Logistic Regression, Decision Tree, and Random Forest.
- The reusable preprocessor fits encoding/scaling before the train/test split; notebook pipelines split first.
- Evaluation uses random stratified session-level splits without device grouping.

ML results from this baseline are implementation benchmarks only, not scientific validation.

## Known baseline maintenance evidence

- No tests or CI.
- Mutable global configuration and global RNG state.
- Duplicate and conflicting configuration/constants.
- Separate synthetic and wired decision paths.
- Stale README counts and roadmap entries.
- Empty `pipeline/README.md`.
- Streamlit is required by the UI but absent from `pipeline/requirements.txt`.
- Generated output is ignored generally, but `IoT_auth_simulator/simulator/data/output/iot_auth_ml_events.json` remains tracked at the baseline commit.

## Baseline classification

`new-main@27135bf` is a sequential, scenario-based synthetic IoT-authentication trace and session-feature generator with a historical per-session FSM, optional side-effect-oriented domain execution, and baseline ML evaluation; it is not a canonical behavioral model or a global discrete-event simulator.
