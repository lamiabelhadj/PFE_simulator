# Scientific contract: Behavioral model v1

## Status and authority

This is a concise implementation-facing summary of the supplied Behavioral-model v1 reconciliation from the externally maintained `02 — Authentication & Behavioral Model`.

`02` remains the scientific authority. This file helps implementation work locate its obligations; it does not replace, extend, or reinterpret `02`. Repository code, tests, comments, notebooks, and historical datasets are implementation evidence only.

## V1 boundary

Behavioral-model v1 requires enough semantics to make supported trace validity decidable without the generator inventing rules. It requires:

- persistent device identity and enrollment context;
- a distinct authentication/session security context;
- explicit semantic events with guards, results, and resulting contexts;
- successful authentication before an authenticated context exists;
- explicit credential/token validity and binding where tokens are used;
- distinct token validation, authorization decision, and protected access;
- enrollment persistence across ordinary session termination;
- benign failure and valid retry/recovery paths;
- scoped renewal/re-authentication during a continuing authenticated operational context;
- anomaly truth based on observable violations of model-defined invariants;
- sufficient history for every within-session or cross-session violation claimed.

V1 does not settle the final phase, state, event, or anomaly vocabulary, a compromised-gateway model, universal re-authorization semantics, or a universal concurrency model.

## Semantic roles and scoped profile

Canonical semantic roles are:

- device/entity;
- authentication and authorization function, conceptually distinct even if colocated;
- protected Resource Server/service;
- mediation, observation, or enforcement roles where required.

Reference-scoped v1 choices are:

- a trusted Gateway/Edge actor;
- MQTT as the current protected communication/application instantiation;
- a bootstrap-secret/PSK-like, proof-of-possession authentication profile with a short-lived token;
- renewal/re-authentication permitted while an authenticated operational context continues.

These scoped choices do not canonize MQTT, PSK, ECDH, a token syntax, existing Python classes, or a universal system architecture. At the semantic level, the MQTT broker is a reference instantiation of a generic protected service/Resource Server role.

## Required state dimensions and persistence

Do not use one monolithic state variable for every device property. Preserve at least:

1. **Persistent device/enrollment context**: identity, enrollment, bootstrap binding, relevant revocation/blocking or long-lived credential facts, and declared cross-session history.
2. **Authentication/session context**: current authentication attempt, challenge, result, authenticated context, token/credential context, protected session, access decision/context, renewal, retry, and termination.

Authentication-trace validity is governed primarily by the authentication/session dimension together with its required persistent context. Neither historical `AuthState` nor historical `DeviceState` independently defines scientific truth.

Ordinary session close, timeout, or disconnect terminates the applicable session-local context but does not erase identity, enrollment, bootstrap association, or history declared persistent. A new protected session does not imply re-enrollment.

`REGISTERED` has no distinct v1 semantic role. It is legacy/superseded implementation residue and maps to the enrolled condition unless `02` later establishes distinct semantics.

## Authentication, credentials, authorization, and access

The reference semantic dependency ordering is:

```text
authentication
-> credential/token establishment
-> token presentation/validation where applicable
-> protected-session establishment
-> authorization decision
-> protected resource access
```

This ordering does not require exactly one event for each step. The following distinctions are mandatory:

- authentication establishes that the applicable authentication requirements were satisfied;
- token issuance establishes a credential context, not permission for every operation;
- token validation checks applicable issuer, integrity, validity, binding, and context properties;
- an active session does not itself authorize a protected request;
- authorization decides whether the authenticated principal/context may perform the requested action on the requested resource;
- access is the resulting protected operation.

An access grant therefore requires the applicable authenticated context, valid credential/token context, and authorization decision. Authorization must not be derived solely from reaching a session state.

Where tokens are used, the representation must expose or imply enough evidence to reason about token-to-authenticated-identity, issuer, scope/permission, validity/freshness, and applicable session/context binding. Cryptographic format is not canonical.

## Renewal and re-authentication

For v1, renewal/re-authentication may occur during a conceptually continuing authenticated operational session. Successful renewal establishes refreshed authentication/token context. Failed renewal must not create refreshed valid credentials.

Subsequent access must still satisfy all applicable authentication, credential/token, and authorization preconditions. V1 establishes neither a universal requirement to re-authorize after every renewal nor a universal permission to reuse prior authorization. If identity, scope, validity, or authorization context changes, the applicable authorization must be reassessed.

## Failure and recovery

Failure is not intrinsically anomalous. Valid behavior may include authentication failure followed by retry, access denial followed by a later valid decision, timeout and retry, transient service failure, or disconnect followed by a new session.

Semantic outcome and state progression must remain coherent:

- failed authentication must not produce an authenticated context;
- access denial must not grant that request;
- timeout/disconnect must not leave a terminated session active;
- a later success requires an explicit subsequent successful path;
- an emitted semantic failure cannot silently advance to the corresponding success context.

## Canonical v1 invariant families

These are invariant families, not a final anomaly catalogue:

| Family | Required meaning | Typical temporal scope |
|---|---|---|
| State/transition validity | Event admissibility under current context and guards | Event/within-session |
| Lifecycle/causal ordering | Required semantic predecessors exist | Within-session; sometimes cross-session |
| Temporal/freshness consistency | Ordering, validity, and freshness relations hold | Event/session/history as declared |
| Identity consistency | Claimed, observed, authenticated, and acting identities are coherent | Event/session |
| Credential/token binding | Credential belongs to the expected identity, issuer, scope, and context | Event/session; potentially cross-session |
| Session continuity/context | Attempts, tokens, identities, and operations are not mixed across incompatible contexts | Session/cross-session |
| Authorization/access preconditions | Protected access has all required security decisions | Event/session |
| Replay/single-use | Material is not reused where its declared domain forbids reuse | Session/cross-session as declared |
| Frequency/history behavior | Repetition is evaluated over an explicit history/window and limit or baseline | Session/history |

No numeric anomaly threshold is canonicalized by v1.

## Current scenario-name disposition

Historical scenario names remain implementation provenance. They do not define anomaly semantics.

| Historical name | V1 disposition |
|---|---|
| `replay_token` | Valid idea, but repair to actual forbidden reuse of previously observed token material; age/expiration alone is not replay |
| `nonce_reuse` | Retainable when actual reuse and the declared uniqueness domain are evidenced |
| `timestamp_inconsistency` | Retainable when a modeled temporal/order/freshness relation is demonstrably violated |
| `duplicate_sequence` | Quarantine under this name until an actual meaningful subsequence is duplicated and linked to its source |
| `impersonation` | Composite scenario provenance; expose the actual identity, binding, or authentication violations separately |
| `identity_token_mismatch` | Separate identity inconsistency from token-binding mismatch; they may co-occur |
| `access_without_auth` | Scenario provenance only unless the exact failed authentication/token-validation/authorization preconditions are recorded |
| `abnormal_failure_rate` | Do not emit as behavioral anomaly without observable history/window and an explicit limit or baseline |
| `abnormal_renewal` | Separate deterministic lifecycle violations from history-dependent behavioral deviation; do not emit the latter without history/baseline |

Specific constraints:

- replay is forbidden reuse, not merely use outside a validity interval;
- nonce reuse must identify the previous occurrence and applicable uniqueness domain;
- timestamp offsets are injection parameters, not semantics;
- one illegal discovery event is not a duplicated sequence;
- IP change alone is not impersonation or identity violation;
- a blocked starting state is not evidence of abnormal failure frequency.

## Scenario intent, anomaly truth, and hard negatives

Keep three concepts separate:

- **scenario/attack intent**: generator metadata about the selected scenario;
- **observable anomaly**: at least one observable canonical invariant violation;
- **normal/hard negative**: observable behavior remains invariant-compliant, even if unusual or produced under attack intent.

An observationally normal “stealth attack” may be retained as scenario-intent metadata or a hard negative. It must not receive positive anomaly ground truth solely because an attack scenario was selected.

## Non-canonical trust score

`trust_score` is optional derived/application/experimental metadata. It must not determine authentication state, authorization state, invariant satisfaction, or anomaly truth unless a later explicit scientific contract defines such a model.

## Explicitly open questions

Implementation must escalate rather than decide:

- final phase count and names;
- final state and event vocabularies;
- final invariant and anomaly catalogues;
- universal re-authentication/re-authorization relationship;
- exact Resource Server/MQTT Broker mapping beyond the v1 abstraction;
- compromised or semi-trusted gateway semantics;
- concurrency beyond required persistence/history;
- replay uniqueness domains not explicitly declared by a supported profile;
- device-specific behavioral thresholds and baselines;
- future invasive or compromised-device attacker models.

## Historical concepts that are not scientific authority

Do not promote the baseline’s exact 23 `AuthState` values, 10 `DeviceState` values, 28 event types, 53 transitions, nine scenario labels, per-session reset behavior, trust formulas, token-age replay proxy, arbitrary timestamp offsets, or MQTT/PSK/ECDH implementation details into canonical definitions.
