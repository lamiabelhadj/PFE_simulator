# Implementation target v1

## Status and authority

This document summarizes the next synchronized generator/dataset milestone derived from the supplied `03 -> C1 Implementation Contract — Behavioral-model v1 Reconciliation`. Behavioral dependencies come from `02 — Authentication & Behavioral Model` and are summarized in `scientific-contract.md`.

`03` remains authoritative for representation, generation, dataset construction, provenance, and executable validation. This document does not authorize Phase 1 and does not resolve open scientific or methodological questions.

## Milestone classification and objective

`new-main@27135bf` is the pre-canonical-sync implementation baseline, not a canonical dataset or simulator version.

The target milestone is a Behavioral-model v1-aligned, scenario-based synthetic authentication trace generator and dataset builder that:

- separates persistent device/enrollment context from authentication/session context;
- produces reconstructable authentication attempts and protected sessions;
- maps implementation events to `02` semantic events;
- records model, generator, schema, run, scenario, and injection provenance;
- derives anomaly ground truth from observable invariant violations rather than scenario intent;
- uses one authoritative semantic synthetic timeline;
- executes semantic and dataset validation;
- physically separates detector-eligible observations from ground truth, debug data, and provenance.

The milestone does not require global discrete-event scheduling, complete MQTT emulation, operational-trace ingestion, empirical realism, a final anomaly taxonomy, a final ML feature set, or a final AI model.

## Required representation

### Persistent context

The implementation must retain, where applicable:

- stable device/entity and profile identifiers;
- enrollment and bootstrap-binding context;
- relevant revocation, blocking, or long-lived credential state;
- history required by each declared cross-session invariant;
- prior token, nonce, or source-event references when their declared uniqueness domain crosses sessions.

Ordinary protected-session termination must not erase this context.

### Authentication/session context

The implementation must represent or reconstruct:

- authentication and re-authentication attempt identity;
- claimed and authenticated identity;
- challenge/nonce and outcome;
- token/credential context and applicable binding;
- protected-session identity, start, end, and termination status;
- authorization decisions and protected operations;
- retry/failure and renewal relationships.

### Dataset event

An event record must support or reference:

- `event_id`;
- canonical semantic event identifier when defined by `02`;
- raw/implementation event identifier where useful for migration provenance;
- timestamp on the authoritative semantic timeline;
- device/context identity;
- `auth_attempt_id` and `session_id` where applicable;
- source semantic security context;
- guard/prerequisite evidence needed for validation;
- result/outcome and resulting semantic context;
- credential, token, challenge, authorization, resource, and action references where relevant;
- provenance link to a controlled injection/transformation where applicable.

The physical schema may normalize persistent records rather than repeat every value, provided the trace remains reconstructable.

## Required lifecycle relationships

The synchronized representation and validator must preserve the scoped `02` dependency ordering:

```text
authentication
-> credential/token context
-> token validation where applicable
-> protected session
-> authorization decision
-> protected access
```

It must not infer authorization solely from session-state reachability. Failure outcomes must agree with resulting contexts. `REGISTERED` must be handled as a legacy alias of enrollment, not a separate target lifecycle concept.

## Provenance and versioning

### Mandatory for the next dataset version

| Provenance item | Requirement |
|---|---|
| `dataset_version` | Dataset build/release identity |
| `schema_version` | Event-record schema identity |
| `feature_schema_version` | Derived-feature schema identity where features are exported |
| `behavior_model_version` | Identifies Behavioral-model v1 or successor |
| generator/code version | Immutable commit or equivalent |
| `run_id` | Generation execution identity |
| configuration snapshot/version | Relevant generation assumptions |
| randomness metadata | Master seed and required derived stream information |
| `scenario_id` and `trace_id` | Scenario instance and generated trace/episode |
| stable device/profile identity | Persistence and reconstruction |
| `session_id` | Protected-session identity where applicable |
| `auth_attempt_id` | Authentication/re-authentication attempt where applicable |
| `anomaly_variant_id` | Injected variant or null |
| invariant ID(s) and family | Where an authoritative mapping exists |
| injection record | Exact target/action/transformation |
| injection parameters | Actual values used |
| observable-violation outcome | Whether a canonical observable violation was produced |
| ground-truth provenance | Why and how each GT label was assigned |
| limitations/capability manifest | Unsupported and planned claims |

When applicable, retain source token/nonce/event IDs, origin/parent session, continuation decisions, hard-negative/scenario-intent classification, and trace-source version.

Version behavioral model, generator, event schema, feature schema, and concrete dataset build/run separately.

## Ground-truth model

For controlled generated traces, ground truth originates at the controlled transformation and invariant-evaluation stage. It must distinguish:

- scenario/attack intent;
- whether an observable invariant violation was produced;
- canonical/scoped invariant family and identifier where available;
- concrete generator-owned anomaly variant;
- exact deviating event(s) or subsequence;
- session/trace label derived under a declared rule;
- normal or hard-negative status;
- causal injection provenance.

Event-level anomaly truth applies only to the actual deviating event set. Valid prefix or continuation events remain event-level normal even when the containing session is anomalous.

The implementation must eliminate baseline inconsistencies including copying session attack flags to every event, positive anomaly labels for no-deviation intent-only traces, top-level/context label disagreement, injections without transformation records, and replay/duplication without links to source material.

## Hard negatives

A hard negative is unusual or suspicious-looking observable behavior that remains valid under `02`.

Potentially valid mechanisms, subject to semantic validation, include benign retries, ordinary failures followed by valid recovery, valid renewal, legitimate partial lifecycles, access denial followed by a later valid request/decision, allowed timing extremes, disconnect followed by a later valid session, and attack-intent traces with no observable violation.

Arbitrary suspicious flags, privileged mismatch indicators, unexplained trust/deviation scores, or target-correlated manipulation are label noise or feature artifacts rather than hard negatives. No prevalence is established by this contract.

## Variant implementation and quarantine

Every supported variant must implement:

```text
scenario family
-> anomaly variant
-> violated invariant(s)
-> observable evidence
-> injection transformation
-> ground truth
```

Current disposition for synchronization:

- repair and retain `nonce_reuse` only with actual reuse, source occurrence, and declared uniqueness domain;
- repair and retain `timestamp_inconsistency` only with an actual modeled temporal relation violation and original/transformed evidence;
- repair `replay_token` to actual forbidden reuse of observed token material;
- quarantine `duplicate_sequence` until a meaningful subsequence is truly duplicated;
- retain `impersonation`, `identity_token_mismatch`, and `access_without_auth` only as scenario provenance while exposing the specific underlying invariant violations;
- disable behavioral `abnormal_failure_rate` until sufficient history/window and an approved deterministic limit or baseline exist;
- disable behavioral `abnormal_renewal` until sufficient history/baseline exists; represent later deterministic renewal violations through their actual invariant families.

Also quarantine positive anomaly truth based only on stealth intent, numeric `trust_score`, token backdating without reuse, a blocked initial state, arbitrary timestamp magnitude, silent success after semantic failure, and authorization inferred from session reachability.

## Authoritative semantic timeline and reproducibility

Use one authoritative simulated timeline for event ordering, credential validity, nonce/challenge freshness, session duration, renewal, and replay-related evidence. Wall-clock execution metadata may be recorded separately but must not determine semantic validity.

Every enforced lifetime or freshness relation must have represented or derivable origin and validity information. Validators must enforce claimed rules; annotation-only helpers cannot substantiate anomaly claims.

Timestamp transformations must identify the relation violated, record original and injected values, and validate the intended resulting violation. Multi-session device histories must share a coherent time domain. Full concurrency is not required for v1.

Scientific minimum reproducibility is semantic reproducibility: recorded source version, configuration, and randomness metadata must reproduce scenario structure, semantic path, outcomes, variant, transformation, labels, and relevant sampled parameters. Byte-identical UUIDs, PSKs, wall-clock metadata, and serialization are desirable but not mandatory unless they influence semantics.

## Field classification and physical separation

Every exported field must be classified as one of:

1. detector-eligible observable data at a declared monitoring point/horizon;
2. retrospective derived feature with derivation and observation horizon;
3. ground truth;
4. debug/privileged validation information;
5. generator/provenance metadata.

Default detector-visible exports must physically exclude ground truth, debug, and provenance fields. Feature metadata must identify event-time observability, session-final observability, retrospective derivation, and future-information dependence.

Historical `attack_type`, `attack_phase`, `severity`, `anomaly_label`, `source_context`, injection fields, privileged mismatch/replay flags, and scenario names belong in ground-truth/debug/provenance outputs unless an external contract separately establishes observability. `trust_score` remains experimental derived metadata. Full-session counts and durations are retrospective features.

## Executable validation

The synchronized version must validate, for supported capabilities:

- transition/state admissibility, required persistent context, and result/state coherence;
- lifecycle and causal predecessors for authentication, credential/token context, session, authorization, access, and renewal;
- temporal ordering, validity, and freshness on the authoritative clock;
- claimed, authenticated, persistent, and acting identity consistency where evidence exists;
- token/credential identity, issuer, validity, scope, and applicable session binding;
- authentication-attempt/session ownership, renewal linkage, termination, and absence of context mixing;
- authentication, credential/token, and authorization prerequisites for granted access;
- source occurrence and declared reuse domain for every replay/single-use claim;
- injection-to-evidence-to-invariant-to-ground-truth consistency;
- event versus session label consistency and intent/anomaly separation;
- required versions, IDs, configuration, randomness, mappings, field classifications, and capability limitations.

Cross-session replay domains not retained, long-window behavioral rates, device-specific baselines, concurrency invariants, operational-log reconstruction, and operational calibration remain future/conditional capabilities and must not be claimed prematurely.

## Minimum synchronized capability

Completion requires all of the following:

1. `behavior_model_version` traceability.
2. Separate persistent and session-local contexts.
3. Distinct scenario, trace, protected-session, and authentication-attempt identities where applicable.
4. Coherent failure/success progression.
5. Distinguishable authentication, token/credential, validation, authorization, and access evidence sufficient for v1 prerequisites.
6. Controlled injection provenance linked to actual observable evidence.
7. No positive anomaly ground truth from intent alone.
8. Repaired supported variants and quarantine of unsupported/misleading labels.
9. Sufficient history for every replay/reuse claim exported.
10. One semantic timeline with claimed temporal relations enforced.
11. Mandatory run, dataset, schema, generator, and model provenance.
12. Physical/default separation of observations from ground truth/debug/provenance.
13. Executable validation for supported v1 invariant families and methodological requirements.
14. A capability/limitations manifest separating implemented, partial, planned, and experimental capabilities.

## Open methodological escalations

Do not decide through implementation convenience:

- final lifecycle, state, event, invariant, anomaly, or variant catalogues;
- universal renewal/re-authorization relation;
- exact Resource Server/MQTT mapping beyond the scoped abstraction;
- compromised-gateway behavior;
- concurrency beyond required persistence/history;
- undeclared replay uniqueness domains;
- operational session reconstruction and adjudication;
- failure/renewal thresholds and device baselines;
- exact normal distributions, hard-negative strategy, and prevalence;
- global discrete-event-engine need and timing;
- calibration against operational/testbed traces;
- future invasive/compromised-device threat models.

## Phase-0 boundary and safe preparation

This document does not begin Phase 1. During Phase 0, safe follow-up work includes source-to-code traceability, output-field inventory, historical-to-target disposition registers, run-manifest and schema proposals, acceptance-test scaffolding, reproducibility/RNG/clock policy proposals, and documentation review templates.

Do not change state semantics, transitions, event vocabulary, authentication, credentials, lifetimes, retries, session boundaries, authorization, anomaly labels, renewal, broker/resource semantics, or gateway trust until a bounded Phase 1 task is explicitly authorized.
