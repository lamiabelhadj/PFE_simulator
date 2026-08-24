# Repository implementation governance

## Purpose

This repository is the implementation branch of a larger scientific programme. It implements externally maintained behavioral and methodological contracts; it does not define or revise those contracts.

The frozen historical implementation baseline is `new-main@27135bf`, tagged `baseline-pre-canonical-sync-27135bf`. Treat it as pre-canonical-sync implementation evidence, not as scientific authority.

The active synchronization branch is `sync/v1-canonical`. Phase names in this repository are implementation-work phases, not scientific or funding deliverable names.

## Authority order

For implementation work, use this order of authority:

1. Explicit task instructions supplied by the programme owners.
2. `02 — Authentication & Behavioral Model` for behavioral semantics.
3. `03 — Simulator & Dataset Methodology` for representation, generation, dataset construction, provenance, and executable validation of `02`.
4. The implementation-target documents in `docs/`, when they faithfully derive from the cited external contracts.
5. Current code, tests, README files, notebooks, comments, and historical outputs as evidence of implementation behavior only.

When sources conflict, do not silently reconcile them. Preserve the evidence, identify the conflict, and escalate the decision to the appropriate external authority.

## Required classification

In design notes, issues, code reviews, migrations, and documentation, distinguish explicitly between:

- **canonical scientific requirement**: a behavioral requirement sourced to `02`;
- **methodological requirement**: a simulator, representation, dataset, provenance, or validation requirement sourced to `03`;
- **currently implemented capability**: behavior verified in repository code or executable output;
- **planned or experimental capability**: an unimplemented proposal that has no canonical status.

Do not use words such as “canonical,” “valid,” or “required” for an implementation assumption unless its external source is identified.

## Semantic escalation rule

If implementation requires a behavioral or methodological decision that the supplied contracts do not cover:

1. stop the affected part of the work;
2. record the exact decision needed and the implementation locations affected;
3. explain why existing code cannot supply scientific authority;
4. preserve compatible historical behavior where practical;
5. request a decision from the owner of `02` or `03`.

Unblocked, non-semantic work may continue independently.

An escalation should use this minimum record:

```text
Decision required | Authoritative owner (02 or 03) | Affected implementation area | Why the supplied contract is insufficient | Safe work that may continue
```

## Historical implementation handling

- Do not promote the historical 23 `AuthState` values, 10 `DeviceState` values, 28 event types, or 53 transitions into canonical definitions.
- `REGISTERED` is legacy/superseded implementation residue, not a separate canonical lifecycle concept.
- Do not delete historical behavior solely because it differs from the synchronized target. Map, quarantine, deprecate, or migrate it with traceable rationale.
- Preserve `new-main@27135bf` and its tag as the comparison point for pre-sync behavior.
- Treat README prose, comments, notebooks, generated data, model results, and the optional wired entity path as potentially stale implementation evidence.

## Behavioral and anomaly boundaries

- Do not invent behavioral semantics to make implementation convenient.
- Attack or scenario names do not define anomaly semantics.
- For controlled generated traces, anomaly ground truth must be established by observable violations of model-defined invariants, as specified by the authoritative contracts.
- Do not equate an injected label, invalid historical FSM transition, detector flag, or attack-specific feature with canonical anomaly truth unless the contracts explicitly establish that relationship.
- Do not treat `trust_score` as authentication state, authorization state, invariant satisfaction, or anomaly truth.
- Keep ground truth, observables, derived features, debugging fields, and provenance separate and identifiable.
- Keep scenario intent distinct from observable anomaly truth. An attack-intent trace with no observable invariant violation is not positive anomaly ground truth.
- Require every supported controlled anomaly variant to map through: variant -> invariant(s) -> observable evidence -> injection transformation -> ground truth.
- Do not claim replay, duplication, frequency, renewal, or cross-session behavior without retaining the evidence and history required to decide it.

## Change discipline

Before implementation changes:

- identify the relevant clauses in `02` and/or `03`;
- identify historical behavior affected;
- state whether the change is semantic, methodological, representational, or purely technical;
- define migration or compatibility treatment for conflicting historical behavior;
- define executable checks that validate the external contract rather than merely snapshotting old behavior.

Do not combine governance, semantic migration, schema redesign, and unrelated cleanup in one change unless explicitly authorized.

## Phase 0 freeze

Until Phase 1 is explicitly authorized, do not change:

- `AuthState` or `DeviceState` semantics;
- FSM transitions;
- lifecycle or event vocabulary;
- authentication or enrollment semantics;
- token or nonce semantics or lifetimes;
- retry or failure semantics;
- session boundaries;
- authorization flow;
- anomaly definitions or labels;
- renewal or re-authentication behavior;
- Resource Server or MQTT Broker semantics;
- gateway trust assumptions.

Phase 0 permits governance documentation, source-to-requirement mapping, inventories, non-mutating validation, test planning, provenance/schema planning, and explicitly approved repository hygiene that does not change behavior.

## Current governance documents

- `docs/scientific-contract.md`: implementation-facing behavioral contract summary. It must remain source-traceable to `02`.
- `docs/implementation-baseline.md`: factual, non-canonical description of `new-main@27135bf`.
- `docs/implementation-target-v1.md`: next milestone requirements derived from `03`, with behavioral dependencies traced to `02`.

The Phase-0 task supplied the reconciled Behavioral-model v1 contract and the `03 -> C1` implementation contract. These repository summaries are implementation-facing derivatives, not replacements for those external authorities. If a later task does not include or identify the applicable source version, preserve the current scoped contract and escalate rather than filling gaps from historical code.
