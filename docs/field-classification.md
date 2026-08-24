# C1.1 current field classification audit

## Scope and limitations

This document inventories fields exported or consumed by the `27135bf` implementation. It is a provisional audit, not a schema design and not a declaration that a field is scientifically observable.

No monitoring point or prediction horizon has yet been approved. A field is classified as `detector-eligible observable` only when it resembles evidence that could be visible at a plausible protocol/network observation point. Fields whose visibility depends materially on the unresolved monitoring point are `ambiguous / semantic decision required`.

Classification categories:

- **detector-eligible observable**: plausible observation at the declared point, subject to later monitoring-point approval;
- **retrospective derived**: computed from observations over a completed event, window, attempt, or session;
- **ground truth**: controlled labels or privileged truth that must not be a default detector input;
- **debug**: internal state, checks, or privileged generator diagnostics;
- **generator/provenance metadata**: generation identity, implementation context, or transformation metadata;
- **ambiguous / semantic decision required**: observability or semantic role cannot be fixed from the supplied contracts.

Prediction-time terms:

- **event-time**: available when the represented event is observed;
- **session-final**: available only when the relevant session/trace outcome is complete;
- **retrospective**: requires aggregation or comparison with history;
- **future-information-dependent**: unavailable at an earlier event-time prediction point because later events/outcomes are used.

## Export surfaces

| Surface | Current structure | Code |
|---|---|---|
| `AuthEvent.to_dict()` | 25 fields per event | `simulator/event_model.py:261-302` |
| Event CSV/DataFrame | 25 event fields plus session-level `attack_type` | `simulator/data/output_views.py:77-130` |
| Nested JSON | Session wrapper, nested event list, and all 67 `SessionContext` fields | `simulator/data/output_views.py:52-70` |
| `SessionContext` | 67 mixed sampled, derived, label, debug, and provenance fields | `simulator/engines/event_engine.py:326-424` |
| Session feature table | 109 columns | `simulator/data/output_views.py:137-345` |
| Reusable ML preprocessing | Feature table minus ad hoc drop lists | `ml/preprocessing.py:35-206` |

## Event record and event CSV

| Field | Current source/meaning | Provisional classification | Prediction time | Audit note |
|---|---|---|---|---|
| `event_id` | Generated UUID | Generator/provenance metadata | Event-time | Event identity is needed for joins but is not a detector signal by default |
| `event_type` | Historical `EventType` value | Detector-eligible observable | Event-time | Raw implementation event, not yet mapped to a semantic event ID |
| `timestamp` | Per-session synthetic timestamp | Detector-eligible observable | Event-time | Semantic authority is compromised by independent/wall clocks and timestamp injection |
| `scenario_id` | Generated scenario UUID | Generator/provenance metadata | Event-time | Scenario identity is not scientific anomaly truth |
| `session_id` | Generated trace-local session UUID | Ambiguous / semantic decision required | Event-time | Useful context key, but currently conflates trace episode and protected session |
| `device_id` | Synthetic persistent device UUID | Ambiguous / semantic decision required | Event-time | Eligibility depends on monitoring point and pseudonymization policy |
| `gateway_id` | Synthetic gateway identifier | Ambiguous / semantic decision required | Event-time | May be observable topology or only generator assignment |
| `auth_server_id` | Hard-coded `auth-01` | Generator/provenance metadata | Event-time | Currently implementation topology metadata |
| `broker_id` | Hard-coded `broker-01` | Generator/provenance metadata | Event-time | Reference-profile topology metadata |
| `previous_state` | Internal historical FSM state | Debug | Event-time | Privileged internal state; enum is non-canonical |
| `new_state` | Internal historical FSM state | Debug | Event-time | Privileged internal result; can conflict with event result |
| `result` | Generated semantic-looking outcome | Ambiguous / semantic decision required | Event-time | Could be observable protocol outcome, but current transient-failure logic can disagree with state |
| `failure_reason` | Generated event/failure string | Ambiguous / semantic decision required | Event-time | Some values resemble protocol outcomes; injected reasons reveal GT |
| `retry_count` | Accumulated current-run retry counter | Retrospective derived | Event-time/retrospective | Uses earlier events and is repeated on later events |
| `token_id` | Synthetic or wired token identifier on selected events | Ambiguous / semantic decision required | Event-time | Eligibility depends on token visibility; also needed for relationship/replay evidence |
| `token_expiry` | Synthetic absolute expiry annotation | Ambiguous / semantic decision required | Event-time | Observable only if the credential/monitor exposes it; current enforcement is inconsistent |
| `token_scope` | Random synthetic scope | Ambiguous / semantic decision required | Event-time | Potentially observable credential property, monitoring/profile dependent |
| `nonce` | Generated challenge nonce on selected events | Detector-eligible observable | Event-time | Plausible protocol evidence; uniqueness domain remains unresolved |
| `identity_claim` | Injected identity claim only for selected anomalies | Ambiguous / semantic decision required | Event-time | A raw claim may be observable, but presence/current generation is attack-coupled |
| `delay_since_previous_event` | Sampled inter-event delay | Retrospective derived | Event-time/retrospective | Available at current event if predecessor time is retained |
| `topic` | Synthetic MQTT topic on session/access events | Detector-eligible observable | Event-time | Reference-profile observable, not universal semantic field |
| `resource_id` | Synthetic resource URI | Ambiguous / semantic decision required | Event-time | Generator-derived alias rather than demonstrated wire evidence |
| `firmware_version` | Device profile value copied to every event | Ambiguous / semantic decision required | Event-time | No implemented event shows how the monitor observes it |
| `source_context` | Literal `normal` or `attack` based on event label | Generator/provenance metadata | Event-time | Directly reveals generation treatment; not detector-visible |
| `anomaly_label` | Historical injected-event label | Ground truth | Event-time | Current GT is not yet canonical-invariant-based |
| `attack_type` | Session context label copied to every event CSV row | Ground truth | Session-final/future-information-dependent | Invalid as event-level detector input; may label valid prefix/continuation events |

## Nested JSON wrapper

| Field | Current source/meaning | Provisional classification | Prediction time | Audit note |
|---|---|---|---|---|
| `scenario_id` | First event's scenario ID | Generator/provenance metadata | Session-final | Duplicates event provenance |
| `scenario_type` | First non-null event anomaly label, otherwise `normal` | Ground truth | Session-final/future-information-dependent | Can disagree with `session_context.attack_type` for stealth scenarios |
| `event_count` | Length of completed event list | Retrospective derived | Session-final/future-information-dependent | Full-trace aggregate |
| `events` | Nested list of 25-field event records | Container; classifications inherited from event fields | Mixed | Observations, debug, GT, and provenance are not physically separated |
| `session_context` | All 67 context fields | Container; classifications below | Session-final | Mixed-purpose privileged object |

## `SessionContext` fields

### Identity and device context

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `claimed_device_id` | Device ID or injected victim ID | Ambiguous / semantic decision required | Event-time/session-final | Raw claim could be observable; current value is attack-coupled |
| `source_ip` | Stable device-pool IP | Detector-eligible observable | Event-time | Plausible network observation |
| `registered_device` | Copy of internal `credential_status` | Debug | Event-time | Privileged registry/credential conclusion, not raw evidence |
| `source_connection_count` | Random integer 1–10 | Ambiguous / semantic decision required | Retrospective | Named as history but not derived from actual observed history |
| `source_diversity` | `1 + source_ip_change` | Retrospective derived | Session-final | Not calculated from an exported observation history |
| `battery_level` | Stable sampled device attribute | Ambiguous / semantic decision required | Event-time | Visibility depends on device telemetry/profile |

### Network and pairing

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `tcp_flags`, `tcp_rtt`, `frame_length`, `tcp_segment_len` | Sampled synthetic connection/network values | Detector-eligible observable | Event-time | Plausible packet evidence, but values are not generated from actual packets |
| `connection_duration` | Full trace span × 1000 | Retrospective derived | Session-final/future-information-dependent | Not a raw TCP duration measurement |
| `packet_rate`, `inter_arrival_time` | Sampled rate and its reciprocal | Retrospective derived | Retrospective/window-final | Require a declared observation window |
| `pairing_result` | Label-dependent random sample | Ambiguous / semantic decision required | Event-time | Could be observable outcome, but current value is independent of event execution |
| `pairing_latency_ms` | Delay of pairing response or fallback challenge | Retrospective derived | Event-time/retrospective | Derivation does not always represent pairing consistently |

### Authentication and MQTT connection context

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `credential_status` | Internal flag directly changed by variants | Debug | Event-time/session-final | Privileged generator conclusion |
| `mqtt_msg_type`, `connect_flags`, `clean_session`, `username_present`, `password_length`, `keep_alive`, `mqtt_version` | Random/session-level MQTT values | Detector-eligible observable | Event-time | Plausible wire fields, but one sampled message type stands for a whole trace |
| `connack_code` | Authentication outcome/failure string | Ambiguous / semantic decision required | Event-time/session-final | Potentially observable, but derived from auth events rather than broker response |
| `auth_result` | Last observed synthetic authentication success | Retrospective derived | Session-final/future-information-dependent | Final session-level result, not per-attempt evidence |
| `auth_latency_ms` | Delay of latest relevant auth result | Retrospective derived | Attempt-final | Requires attempt boundaries that are currently absent |
| `failed_auth_count` | Event counter plus optional direct benign manipulation | Retrospective derived | Session-final/future-information-dependent | Can lack matching failure events |

### Authorization and resource request

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `requested_topic`, `operation`, `requested_qos`, `retain_flag` | Synthetic MQTT request properties | Detector-eligible observable | Event-time | Reference-profile request evidence |
| `topic_length` | Length of requested topic | Retrospective derived | Event-time | Immediate deterministic derivation |
| `granted_qos` | Set equal to requested QoS | Ambiguous / semantic decision required | Event-time | Could be an observable decision result; current derivation is unconditional |
| `authorization_result` | Set to 1 on `SESSION_OPENED` | Debug | Session-final | Privileged and semantically conflicting derivation |
| `topic_scope_violation` | Internal random flag on some access denials | Debug | Event-time/session-final | Generator/internal decision, not raw request evidence |

### MQTT/session activity

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `message_id`, `duplicate_flag`, `payload_length`, `payload_hash`, `qos_level` | Sampled MQTT/message properties | Detector-eligible observable | Event-time | `payload_hash` is a derived representation of sampled payload bytes but event-local |
| `message_rate`, `byte_rate` | Sampled rate; byte rate derives rate × payload size | Retrospective derived | Retrospective/window-final | Requires declared observation window |
| `session_duration` | Full event timestamp span | Retrospective derived | Session-final/future-information-dependent | Duplicates later `session_duration_s` under another name |

### Re-authentication, trust, and detector-style signals

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `trust_score` | Post-hoc weighted formula over flags plus noise | Retrospective derived | Session-final/future-information-dependent | Experimental metadata; cannot define state or GT |
| `behavior_deviation_score` | Post-hoc formula from trust/IP/replay flags | Retrospective derived | Session-final/future-information-dependent | Experimental detector-style score |
| `re_auth_required` | Set when a renewal event occurs | Debug | Session-final | Does not represent an independently evaluated requirement |
| `gateway_decision` | Post-hoc decision from internal flags | Debug | Session-final | Not the wired gateway's actual decision |
| `session_present` | Set on synthetic session-open event | Ambiguous / semantic decision required | Event-time/session-final | Could be MQTT CONNACK evidence, but current source is internal state reachability |
| `source_ip_change` | Direct attack/false-positive flag | Debug | Session-final | No exported IP history substantiates the change |
| `replay_window_violation` | Direct attack/false-positive flag | Debug | Session-final | Privileged detector/GT-related flag; current replay semantics conflict with v1 |

### Step latencies

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `s1_latency_ms`, `s2_latency_ms`, `s3_latency_ms`, `s4_latency_ms`, `s5_latency_ms`, `s6_latency_ms` | Selected event delays mapped to historical phases | Retrospective derived | Phase-final/session-final | Historical phase meanings are not canonical; later events may overwrite some values |

### Labels and variant-specific diagnostics

| Field(s) | Current source | Classification | Prediction time | Audit note |
|---|---|---|---|---|
| `attack_type`, `attack_phase`, `severity` | Historical scenario specification and severity map | Ground truth | Session-final/future-information-dependent | Scenario provenance currently used as GT; not detector input |
| `token_age_at_replay`, `nonce_age_at_reuse`, `timestamp_delta_s`, `duplicate_session_count` | Direct variant enrichment or false-positive manipulation | Debug | Session-final | Privileged injection/diagnostic fields; not raw detector evidence |
| `identity_claim_mismatch`, `token_device_mismatch`, `unauthorized_access_attempt` | Direct privileged variant flags | Debug | Session-final | Internal conclusions that reveal intended violation |
| `steps_before_access` | Injection position copied for one variant | Debug | Session-final | Generator implementation detail, not causal predecessor evidence |

## Session feature table: 109 columns

The session feature table contains four identifier columns, 49 copied `SessionContext` fields, 48 general aggregates/counts/signals, and eight variant-specific diagnostic fields.

### Identifiers

| Fields | Classification | Prediction time |
|---|---|---|
| `scenario_id` | Generator/provenance metadata | Session-final |
| `session_id`, `device_id`, `gateway_id` | Ambiguous / semantic decision required | Session-final |

### Copied context fields

The following fields retain the `SessionContext` classifications above:

```text
claimed_device_id, source_ip, registered_device, source_connection_count,
battery_level, tcp_flags, connection_duration, tcp_rtt, packet_rate,
inter_arrival_time, frame_length, tcp_segment_len, pairing_result,
pairing_latency_ms, mqtt_msg_type, connect_flags, clean_session,
username_present, password_length, keep_alive, mqtt_version, connack_code,
auth_result, auth_latency_ms, failed_auth_count, requested_topic, topic_length,
operation, authorization_result, topic_scope_violation, retain_flag,
message_id, duplicate_flag, payload_length, payload_hash, qos_level,
message_rate, byte_rate, trust_score, re_auth_required, session_present,
source_ip_change, replay_window_violation, s1_latency_ms, s2_latency_ms,
s3_latency_ms, s4_latency_ms, s5_latency_ms, s6_latency_ms
```

Seven `SessionContext` fields are omitted from the feature table: `source_diversity`, `credential_status`, `requested_qos`, `granted_qos`, context `session_duration`, `gateway_decision`, and `behavior_deviation_score`.

### Full-session temporal aggregates

| Fields | Classification | Prediction time |
|---|---|---|
| `session_duration_s`, `mean_delay_s`, `max_delay_s`, `min_delay_s` | Retrospective derived | Session-final/future-information-dependent |

### Event counts

All fields below are retrospective derived and session-final/future-information-dependent:

```text
n_events,
n_discovery, n_gateway_advertisement, n_pairing_request, n_pairing_response,
n_enrollment_request, n_enrollment_confirmed, n_registration_request,
n_registration_confirmed, n_authentication_request, n_challenge_sent,
n_nonce_received, n_response_sent, n_authentication_success,
n_authentication_failure, n_token_issued, n_token_presented,
n_token_validated, n_token_rejected, n_renewal_request, n_token_expired,
n_session_opened, n_session_closed, n_access_request, n_access_granted,
n_access_denied, n_retry, n_timeout, n_disconnect
```

The event-specific names are historical implementation vocabulary; their counts are not canonical lifecycle features.

### State, failure, reuse, and identity aggregates

| Fields | Classification | Prediction time | Audit note |
|---|---|---|---|
| `visited_states`, `reached_session_open`, `reached_access_granted`, `reached_authenticated` | Retrospective derived | Session-final/future-information-dependent | Based on privileged non-canonical FSM states |
| `n_failures`, `n_retries`, `failure_rate` | Retrospective derived | Session-final/future-information-dependent | Can include result/state inconsistencies |
| `n_token_reuses`, `n_nonce_reuses` | Retrospective derived | Session-final/future-information-dependent | Count repeated appearances, not validated semantic replay domains |
| `identity_mismatch`, `n_state_jumps` | Debug | Session-final/future-information-dependent | Privileged cross-event checks using internal identity/state |

### Labels and variant diagnostics

| Fields | Classification | Prediction time |
|---|---|---|
| `is_anomaly`, `attack_type`, `attack_phase`, `severity` | Ground truth | Session-final/future-information-dependent |
| `token_age_at_replay`, `nonce_age_at_reuse`, `timestamp_delta_s`, `duplicate_session_count`, `identity_claim_mismatch`, `token_device_mismatch`, `unauthorized_access_attempt`, `steps_before_access` | Debug | Session-final/future-information-dependent |

## Relevant ML preprocessing inputs

The reusable preprocessor receives the complete 109-column session feature table. For either supported target it drops 13 present columns, leaving up to 96 model inputs before optional leakage removal.

### Always removed from model input

| Fields | Reason/classification |
|---|---|
| `scenario_id`, `session_id`, `device_id`, `gateway_id`, `message_id`, `payload_hash` | Identifier/provenance handling |
| `claimed_device_id`, `source_ip`, `requested_topic` | High-cardinality fields; numeric proxies are assumed |
| `anomaly_type`, `anomaly_phase` | Listed aliases, but absent from the current feature schema |

### Target-dependent removal

| Target | Removed target/label fields |
|---|---|
| Binary `is_anomaly` | `is_anomaly`, `attack_type`, `attack_phase`, `severity` |
| Multiclass `attack_type` | `attack_type`, `is_anomaly`, `attack_phase`, `severity` |

### Still admitted by default

Unless optional `drop_leakage=True` happens to remove them, the default model input still admits:

- privileged/debug variant fields such as `token_device_mismatch`, `identity_claim_mismatch`, `unauthorized_access_attempt`, `timestamp_delta_s`, and related fields;
- debug flags such as `replay_window_violation`, `registered_device`, `authorization_result`, and `topic_scope_violation`;
- retrospective and future-information-dependent full-session aggregates and event counts;
- experimental `trust_score`;
- fields whose observability is unresolved.

The optional leakage list is empirical and incomplete; it is not a field-classification or observability policy. `gateway_decision` is configured as a categorical ML field but is not present in the 109-column feature table.

The reusable preprocessor fits encoding and scaling on the entire DataFrame before train/test splitting. This audit records the issue but makes no preprocessing change.

## Classification escalations

The following decisions are required before a definitive detector-visible schema can be approved:

1. monitoring point(s) and actor visibility;
2. prediction horizon(s), including event-time versus attempt/session-final use;
3. which identity, token, scope, expiry, firmware, and resource properties are actually observable at each point;
4. whether protocol result/reason fields are raw evidence or internal reconstructions;
5. which state/context evidence is observable versus privileged validator output;
6. permitted pseudonymous identifiers and cross-session linkage;
7. approved derivation windows for rates, counts, delays, and behavioral history;
8. default physical file/join structure for observations, derived features, GT, debug, and provenance.
