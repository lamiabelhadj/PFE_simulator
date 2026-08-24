# C1.1 historical implementation disposition audit

## Scope

This document proposes dispositions for historical constructs evidenced at `new-main@27135bf`. It does not modify, delete, rename, or refactor any construct. A disposition describes future controlled treatment under the accepted contracts; it does not authorize Phase 1.

Disposition meanings:

- `KEEP`: already compatible for its scoped role;
- `MAP`: retain the implementation construct or raw evidence while mapping it to authoritative semantics;
- `MIGRATE`: representation or architecture must be replaced or substantially reworked;
- `DEPRECATE`: legacy construct should disappear through controlled migration;
- `QUARANTINE`: may remain as historical, debug, experimental, or provenance material but must not represent canonical truth;
- `ESCALATE`: supplied contracts do not determine the correct implementation.

Where a primary disposition is possible but a later detail remains open, the table gives the primary disposition and separately marks semantic escalation.

## Core behavioral and execution constructs

| Historical construct | Evidence/location | Current role/problem | Proposed disposition | Required direction | Semantic escalation? |
|---|---|---|:---:|---|:---:|
| Stable `Device` identity and profile object | `core/device.py:54-106`; `runner.py:41-42` | Provides reusable device ID, IP, PSK, profile, battery, firmware, and trust fields | `KEEP` | Keep stable device identity/profile capability as persistent implementation context; separately classify each exported attribute | No |
| `AuthState` (23 values) | `event_model.py:113-157` | Monolithic enum mixes enrollment, authentication, token, access, session, failure, revocation, and blocking | `MIGRATE` | Replace its authority with separate persistent and authentication/session semantic contexts; retain raw values for migration evidence | Yes — final semantic state vocabulary/mapping |
| `DeviceState` (10 values) | `core/device.py:39-49` | Coarse device lifecycle alternative that is not driven by event generation | `MAP` | Map any genuinely persistent/operational concepts to the persistent dimension; do not use it as another authentication FSM | Yes — member-level mapping |
| `REGISTERED` state | `event_model.py:141`; `state_machine.py:91-92` | Distinct historical enum member without a distinct v1 role | `DEPRECATE` | Controlled migration to the enrolled condition; preserve raw legacy decoding while historical datasets remain supported | No |
| `REGISTRATION_REQUEST` / `REGISTRATION_CONFIRMED` | `event_model.py:76-78`; `state_machine.py:87-92` | Legacy coarse event layer alongside discovery/pairing/enrollment | `DEPRECATE` | Preserve as raw legacy event names during mapping, then remove from target semantic flow unless external evidence supplies a distinct role | Yes — exact event mapping |
| Current `EventType` vocabulary (28 values) | `event_model.py:39-106` | Historical raw event names used directly as dataset event types | `MAP` | Retain raw event identifier for provenance while adding authoritative semantic mapping | Yes — final semantic event IDs/vocabulary |
| Current 53-entry transition table | `state_machine.py:72-168` | Encodes historical validity as unguarded state/event lookup | `MIGRATE` | Move validity to contract-defined contexts and guards; preserve table as baseline compatibility evidence/tests | Yes — final guards and state/event mapping |
| `StateMachine.force()` and internal fabricated disconnect history | `state_machine.py:352-359` | Mutates state outside validation and records a non-exported synthetic `DISCONNECT` | `QUARANTINE` | Keep only as legacy injection machinery during migration; never treat force history as canonical evidence | No |
| Per-session `StateMachine()` reset | `event_engine.py:487`; `runner.py:74-100` | Every trace starts `UNREGISTERED`, losing enrollment and history distinctions | `MIGRATE` | Introduce persistent device context and separate attempt/session contexts; preserve session-local validation where appropriate | No |
| Sequential scenario runner | `runner.py:63-109` | Executes shuffled sessions sequentially without DES | `KEEP` | V1 does not require global DES; add coherent semantic time and persistent histories without unnecessary scheduler expansion | No |
| `ScenarioSpec` / `ScenarioEngine` | `scenario_engine.py:248-556` | Useful declarative scenario intent, but currently embeds attack truth and invalid-transition semantics | `MAP` | Retain as generator-owned scenario/variant provenance; separate intent, transformation, invariant result, and GT | Yes — final variant catalogue and semantic mappings |
| `AuthEvent` record | `event_model.py:174-302` | Useful event carrier mixing raw observation, internal state, GT, and provenance | `MAP` | Retain raw-event evidence and stable IDs while mapping to semantic contexts and separating field classes physically | Yes — final event mapping and observability |
| `SessionContext` (67 fields) | `event_engine.py:326-424` | Monolithic mixture of sampled observations, final aggregates, labels, debug flags, provenance, and experimental scores | `MIGRATE` | Split into reconstructable session/context representation plus separate observation, derived, GT, debug, and provenance views | Yes — field observability and final schema |
| `session_id` as trace/session grouping | `event_model.py:216-218`; `event_engine.py:489` | One UUID effectively identifies both trace episode and protected session | `MIGRATE` | Distinguish `trace_id`, protected `session_id`, and `auth_attempt_id`; preserve old ID as legacy provenance | No |
| Device reuse across sessions | `runner.py:41-42,74-76` | Provides potential persistence but current generated semantics still reset | `KEEP` | Use stable device identity as basis for coherent histories; do not infer current hidden state as canonical | No |

## Temporal, credential, actor, and authorization constructs

| Historical construct | Evidence/location | Current role/problem | Proposed disposition | Required direction | Semantic escalation? |
|---|---|---|:---:|---|:---:|
| `TemporalEngine` | `engines/temporal_engine.py` | Per-session counters and predicates; conflicting lifetimes; most predicates annotation-only | `MIGRATE` | Make one semantic clock authoritative and enforce every claimed supported temporal rule; separate annotation-only helpers | Yes — undeclared validity/reuse domains |
| Per-`EventEngine` wall-clock start | `event_engine.py:455-471`; `runner.py:74-100` | Independent start times prevent coherent device history | `MIGRATE` | Use a run/device-history semantic timeline and record wall-clock execution separately | No |
| Configured and hard-coded token/nonce lifetimes | `config/settings.py:136-159`; `temporal_engine.py:34-55`; `core/auth_server.py:152-165` | Multiple contradictory values and attack-dependent lifetime | `MIGRATE` | Source each supported profile rule from approved configuration and enforce it consistently | Yes — final profile values/domains |
| `trust_score` fields/formulas | `core/device.py:104-105,194-205`; `event_engine.py:277-319,909-918` | Two incompatible meanings; post-hoc detector-style score | `QUARANTINE` | Keep only as optional experimental/derived metadata outside canonical state and GT | No |
| Trusted gateway role | `core/gateway.py:60-73` | Matches scoped v1 trusted Gateway/Edge assumption | `KEEP` | Preserve only as reference-scoped profile; do not generalize to universal programme semantics | No |
| MQTT broker / protected-service implementation | `core/auth_server.py:251-449` | Current reference service, with MQTT-specific prefix checks and session mechanics | `MAP` | Map to generic protected service/Resource Server semantics while retaining MQTT as the reference instantiation | Yes — exact mapping beyond minimum abstraction |
| PSK, ECDH, and local token format | `core/device.py:72-98,150-184`; `core/auth_server.py:25-45,86-170` | Concrete reference crypto/profile implementation | `MAP` | Retain as reference-profile mechanics; map to bootstrap, PoP/binding, issuer, validity, and scope relationships without canonizing format | Yes — exact scoped binding requirements |
| Optional wired entity path | `runner.py:49-61,78-87`; `core/session_driver.py` | Exercises entities but ignores most enforcement outcomes when emitting data | `QUARANTINE` | Keep as experimental/reference execution evidence until its decisions either govern a synchronized trace or are explicitly separated as a validation harness | No |
| Current authorization derivation | `event_engine.py:794-803,920-928`; `session_driver.py:136-140` | Session open sets authorization success; wired ABAC result is ignored | `MIGRATE` | Represent token validation, authorization decision, and access separately and enforce applicable access prerequisites | No |
| Current token identity/validation path | `core/auth_server.py:204-231`; `MQTTBroker.connect()` at `auth_server.py:280-321` | Token record exists, but parsed/stored identity is not checked against connecting device | `MIGRATE` | Enforce approved token-to-identity/issuer/scope/context relationships | Yes — applicable token/session binding |
| Current nonce/replay caches | `core/gateway.py:90-94,306-324,366-375`; `temporal_engine.py:128-154` | Useful history mechanisms, but domains and time sources conflict and do not establish exported GT | `MAP` | Retain cache capability behind declared uniqueness domains and source-event provenance on the semantic clock | Yes — uniqueness domains |

## Failure, ground-truth, output, and ML constructs

| Historical construct | Evidence/location | Current role/problem | Proposed disposition | Required direction | Semantic escalation? |
|---|---|---|:---:|---|:---:|
| Explicit benign retry and denial/recovery flows | `scenario_engine.py:88-109,151-158,321-363` | Demonstrates failure ≠ anomaly and later recovery | `KEEP` | Preserve the concept; later add attempt/request identity and executable coherence checks | No |
| Random transient-failure behavior | `event_engine.py:1078-1092` | Emits failure while state machine may advance to nominal success | `MIGRATE` | Separate ancillary implementation issues from semantic failure, or prevent success-state progression until explicit success | No |
| Auto-block after three failures | `state_machine.py:267-334` | Historical deterministic rule and threshold | `QUARANTINE` | Do not treat the threshold or blocked state as canonical frequency semantics; retain only as legacy/profile evidence pending approval | Yes — limit/window semantics |
| “Stealth attack” mechanism | `event_engine.py:163-192,550-558` | No injection/observable deviation but positive session attack label | `QUARANTINE` | Retain attack intent only as provenance; observationally valid traces may become hard negatives, not positive anomaly GT | No |
| Benign false-positive flag manipulation | `event_engine.py:675-689` | Directly changes replay/failure/IP flags without corresponding event evidence | `QUARANTINE` | Do not call this a hard negative unless a coherent invariant-valid trace produces the evidence | Yes — approved hard-negative methodology/prevalence |
| `anomaly_label`, `attack_type`, `attack_phase`, `severity`, `is_anomaly` model | `event_model.py:247-255`; `event_engine.py:933-935`; `output_views.py:303-319` | Historical scenario names are copied into event/session GT | `MIGRATE` | Separate intent, variant, invariant result, deviating events, session rule, and GT provenance | Yes — final invariant/anomaly IDs |
| Attack-specific signal fields | `SessionContext` at `event_engine.py:411-421`; `output_views.py:321-343` | Privileged flags/parameters mixed into the ML feature table | `QUARANTINE` | Move to debug/GT/provenance outputs; retain raw detector evidence separately | No |
| Nested JSON / event CSV / session CSV / Parquet formats | `output_views.py:52-130,137-388`; `exporter.py:18-45` | Useful transport formats, but each mixes field classes or lacks versions | `KEEP` | Formats may remain; schemas, manifests, physical separation, and joins must migrate | No |
| Current 109-column feature table | `output_views.py:164-345` | Mixes identifiers, observables, retrospective features, GT, debug, and future information | `MIGRATE` | Build classified/versioned derived views with explicit horizons; no silent compatibility break | Yes — monitoring point and feature contract |
| Reusable ML preprocessing | `ml/preprocessing.py:35-206` | Ad hoc drop lists; privileged/future fields retained; transformations fit before split | `MIGRATE` | Split before fitting and consume an approved detector-input manifest in a later authorized task | No |
| Global mutable `cfg` and process-wide RNG | `config/settings.py:265-277`; `runner.py:39`; CLI/UI mutation | Configuration is not isolated or persisted; seed does not cover semantic identifiers/times | `MIGRATE` | Introduce immutable run snapshot and semantic reproducibility metadata while preserving reviewed defaults until authorized | No |
| Historical generated datasets and notebooks | `simulator/data/output/`; `ml/*.ipynb` | Pre-sync evidence and experiments with stale schemas/labels | `QUARANTINE` | Preserve/version externally or as explicit baseline evidence; never use as scientific authority or synchronized GT | No |

## Nine historical anomaly labels

| Historical label | Current implementation | Proposed disposition | Required contract-directed treatment | Semantic escalation? |
|---|---|:---:|---|:---:|
| `replay_token` | Invalid token presentation plus backdated issuance and age/replay flags | `MIGRATE` | Generate actual reuse of linked, previously observed token material in a declared forbidden context; distinguish expiration/freshness from replay | Yes — reuse/binding domain |
| `nonce_reuse` | Re-emits current nonce on an invalid `NONCE_RECEIVED` event and records age | `MAP` | Retain only when source occurrence, repeated material, attempt/context, and declared uniqueness domain are recorded and validated | Yes — exact uniqueness domain |
| `timestamp_inconsistency` | Rewinds injected event timestamp by 400–900 seconds | `MAP` | Map to an approved temporal/order/freshness relation; preserve original/transformed values; offset remains a parameter | Yes — exact semantic event/relation mapping |
| `duplicate_sequence` | Emits one invalid discovery event and sets a counter | `QUARANTINE` | Disable the scientific label until an actual meaningful subsequence is duplicated and source-linked; otherwise later map to state/ordering violation | Yes — meaningful sequence unit |
| `impersonation` | Bundles victim claim, IP change, invalid credential, and skipped validation/session open | `QUARANTINE` | Keep scenario-family provenance only; label actual identity, binding, or authentication violations separately | Yes — final invariant IDs/mapping |
| `identity_token_mismatch` | Bundles foreign token, victim claim, credential invalidity, and two mismatch flags | `QUARANTINE` | Separate identity inconsistency and token-binding mismatch; allow co-occurrence without treating bundle as atomic truth | Yes — exact binding/context rules |
| `access_without_auth` | Invalid access request before normal authentication plus one broad flag | `QUARANTINE` | Keep scenario provenance only after recording the exact missing authentication, validation, credential, or authorization prerequisites | Yes — profile-specific access prerequisites/mapping |
| `abnormal_failure_rate` | Starts from forced `BLOCKED` and may use high traffic rates; no antecedent failure history | `QUARANTINE` | Disable behavioral GT until observable history/window and approved explicit limit or baseline exist | Yes — threshold/window/baseline |
| `abnormal_renewal` | Invalid renewal request from a historical state; no behavioral history | `QUARANTINE` | Separate deterministic lifecycle/credential violation from history-dependent renewal deviation; disable the latter meanwhile | Yes — baseline/window and exact renewal mapping |

## Constructs recommended for quarantine or deprecation first

Priority quarantine candidates, because they currently risk representing non-canonical truth:

1. stealth-positive anomaly labels;
2. `duplicate_sequence`, `abnormal_failure_rate`, and behavioral `abnormal_renewal` GT;
3. composite `impersonation`, `identity_token_mismatch`, and broad `access_without_auth` as atomic GT;
4. `trust_score` as anything beyond experimental derived metadata;
5. attack-specific signal fields in detector-visible feature exports;
6. backdated-token replay and blocked-state frequency proxies;
7. the side-effect-only wired path as evidence that emitted decisions were enforced;
8. `StateMachine.force()` history as trace evidence;
9. direct benign “false-positive” flag manipulation.

Controlled deprecation candidates:

1. distinct `REGISTERED` state;
2. legacy registration request/confirmation layer, subject to raw historical decoding and final event mapping.

## Semantic escalations retained

No disposition resolves the following open decisions:

- member-level mapping and final vocabulary for persistent/session states;
- final semantic event and invariant identifiers;
- exact token/session/context binding rules;
- token, nonce, and sequence uniqueness domains;
- universal renewal/re-authorization relation;
- exact Resource Server/MQTT mapping beyond the reference abstraction;
- monitoring points and field observability;
- behavioral thresholds/baselines;
- hard-negative strategy and prevalence;
- final anomaly-variant catalogue and meaningful duplicated sequence unit.

## Readiness conclusion

The repository is ready for bounded planning around migration architecture, provenance, schema separation, validation interfaces, and explicit quarantines. It is not ready for behavioral refactoring until the escalated mappings and first bounded Phase 1 slice are approved.
