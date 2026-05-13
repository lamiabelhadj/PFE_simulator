# Future Modifiable Variables and Enhancement Notes

This file documents project variables, constants, and design choices that future developers may want to modify. It is meant as a quick map of what can evolve, where it currently lives, and what should be considered before changing it.

## Configuration-Level Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Number of simulated devices | `20` in config, `5` in `main.py` helper | `config/settings.yaml`, `main.py` | Load the value from config everywhere; scale dataset size for ML experiments. |
| Normal events per device | `5` | `config/settings.yaml` | Use to balance normal/anomalous class distribution. |
| Replay events per device | `2` | `config/settings.yaml` | Increase for replay-heavy datasets or reduce for imbalanced realistic datasets. |
| Export directory | `data/generated` | `config/settings.yaml`, `main.py` | Make output path fully config-driven. |
| Export formats | `csv`, `json` | `config/settings.yaml`, exporters | Add Parquet, SQLite, or streaming export for larger datasets. |

## Device and Identity Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Device types | `sensor`, `actuator`, `gateway`, `controller` | `config/settings.yaml`, `main.py` | Add cameras, meters, wearables, industrial controllers, vehicles, or medical devices. |
| Resource classes | `constrained`, `moderate`, `high_capability` | `config/settings.yaml`, `main.py` | Add CPU, RAM, battery ... |
| Identity methods | `preshared_key`, `username_password` | `config/settings.yaml`, `device.py`, `event_generator.py` | Add `certificate`, `raw_public_key`, `oauth_client_credentials`, or hardware-backed identity. |
| Known registry status | `known_to_registry=True` for generated devices | `main.py`, `device.py` | Generate unknown/rogue devices to simulate impersonation and unauthorized enrollment. |


## Authentication and Token Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Token expiration | `3600` seconds in config, one hour in generator | `config/settings.yaml`, `event_generator.py`, `auth_server.py` | Make all token TTLs config-driven; test short-lived tokens and refresh behavior. |
| Token scope | `sensors/*` | `normal_flow.py`, `event_generator.py` | Generate per-device, per-operation, or per-topic scopes. |
| Token reuse behavior | Token has a `used` flag | `token.py`, `mqtt_broker.py`, `replay_attack.py` | Model one-time tokens, refresh tokens, token revocation, or token binding. |
| Proof of Possession | Currently not implemented | README, future auth logic | Add PoP later to compare replay detection before and after stronger token binding. |
| Credential status values | `valid`, `invalid`, `expired`, `stolen`, `malformed` | `event_generator.py`, `event.py` | Add more precise failure reasons, e.g. `revoked`, `weak_password`, `unknown_issuer`. |

## MQTT Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| MQTT versions | `3`, `4`, `5`; normal flow currently uses `4` | `config/settings.yaml`, `normal_flow.py`, `mqtt_broker.py`, `event_generator.py` | Fix one version for controlled experiments or randomize versions using config. |
| QoS levels | `0`, `1`, `2` | `config/settings.yaml`, `event_generator.py`, `normal_flow.py` | Model QoS downgrade, unexpected QoS escalation, or broker-specific QoS policies. |
| Clean session flag | Usually `True`; replay uses `False` | `normal_flow.py`, `replay_attack.py`, `mqtt_broker.py` | Add MQTT 5 session expiry interval and persistent-session abuse scenarios. |
| Keep-alive interval | `60` seconds | `normal_flow.py`, `replay_attack.py`, `mqtt_broker.py`, `session.py` | Randomize by device class; detect abnormal keep-alive behavior. |
| CONNACK code | `0` for accepted, `1-5` for failures | `mqtt_broker.py`, `event_generator.py` | Expand for MQTT 5 reason codes. |
| MQTT message type | `DISCOVERY`, `CONNECT`, `PUBLISH` in generated events | `event_generator.py` | Add `SUBSCRIBE`, `UNSUBSCRIBE`, `PINGREQ`, `DISCONNECT`, and MQTT 5 properties. |
| Retain flag | Usually `False` | `event_generator.py` | Add retained-message misuse or stale retained payload attacks. |

## Hashing and Payload Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Hash function | `BLAKE2s` | `event.py`, `event_generator.py`, `csv_exporter.py`, README | Keep as BLAKE2s for lightweight IoT-friendly hashing, or compare with SHA-256/BLAKE3 in experiments. |
| Payload hash digest size | `16` bytes / 32 hex chars | `event_generator.py` | Increase digest size for lower collision risk; expose as config. |
| Payload length | Random `50-1000` bytes | `event_generator.py` | Use device-type payload profiles, binary payloads, compressed payloads, or malformed payload sizes. |
| Payload hash seed | Synthetic event metadata plus random value | `event_generator.py` | Hash actual payload bytes from broker publishes for stronger realism. |
| Message ID format | `msg_{device_id}_{random_number}` | `event_generator.py` | Use MQTT packet identifiers or deterministic replayed IDs for replay detection. |

## Network and Timing Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| TCP RTT | Random `15-120` ms | `event_generator.py` | Use distributions by network type: LAN, Wi-Fi, LPWAN, cellular, satellite. |
| Packet rate | Normal `0.5-3.0`, anomaly higher | `event_generator.py` | Make scenario-specific profiles for flood, slow auth, and on-off attacks. |
| Inter-arrival time | Random `0.2-2.0` seconds | `event_generator.py` | Use bursty traffic models or real trace-inspired distributions. |
| Frame length | Random `64-512` bytes | `event_generator.py` | Tie frame length to MQTT packet type and payload size. |
| TCP segment length | `frame_length - 54` | `event_generator.py` | Replace with protocol-aware packet modeling. |
| Connection duration | Random baseline, longer for anomalies | `event_generator.py`, `session.py` | Model device uptime, reconnection loops, and slow-session abuse. |
| Pairing latency | Normal `40-250` ms, anomaly `800-3000` ms | `event_generator.py` | Make pairing latency depend on device resource class and key exchange method. |
| Authentication latency | Random `50-200` ms | `event_generator.py` | Vary by identity method, auth server load, TLS handshake, and network conditions. |

## Authorization and Topic Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Authorization result | `allowed` or `denied` | `event.py`, `event_generator.py` | Keep simple for now; later replace with ACL, RBAC, or ABAC if the project scope needs it. |
| Topic pattern | `sensors/device_{device_id}/data` | `normal_flow.py`, `replay_attack.py`, `event_generator.py`, `gateway.py` | Add command topics, telemetry topics, shared subscriptions, and wildcard topic abuse. |
| Topic length | Derived from requested topic | `event_generator.py` | Use as a malformed-topic feature or topic-scoping anomaly signal. |
| Topic scope violation | Random for anomalies | `event_generator.py` | Derive from token scope and requested topic instead of random selection. |
| Operation | Currently mostly `publish` | `event_generator.py`, `gateway.py` | Add subscribe/unsubscribe/connect/disconnect operations. |

## Anomaly and Attack Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Attack type | `normal` or `replay` currently generated | `event.py`, `event_generator.py`, `replay_attack.py` | Add impersonation, brute force, DoS, DDoS, malformed packet, unauthorized access, slow auth, session hijacking. |
| Attacker type | `non-invasive` for replay | `replay_attack.py` | Add `invasive`, `physical`, `remote`, `insider`, or `botnet`. |
| Severity | `low`, `medium`, `high` | `event.py`, `event_generator.py`, `replay_attack.py` | Add `critical`; compute severity from impact and confidence. |
| Trust score | Normal close to `1.0`, replay lower | `event.py`, `event_generator.py` | Use a real trust-update formula over time. |
| Behavior deviation score | Normal low, replay high | `event.py`, `event_generator.py` | Compute from baseline statistics instead of random ranges. |
| Replay window violation | `True` for replay events | `event_generator.py`, `replay_attack.py` | Add configurable replay windows and timestamp checks. |
| Source IP change | `True` for replay events | `event_generator.py` | Generate multi-source attackers, NAT behavior, roaming devices, or hijacked sessions. |
| Failed auth count | Random for anomalous auth | `event_generator.py` | Track counts per device/source over time instead of generating per event. |

## Scenario and Flow Variables

| Variable / Area | Current Value | Location | Possible Future Changes |
| --- | --- | --- | --- |
| Lifecycle states | Discovery through active/terminated, plus failed | `state_machine.py` | Add explicit token refresh, revocation, quarantine, and recovery states. |
| Normal active messages | `3` messages per normal session | `normal_flow.py`, `event_generator.py` | Make message count config-driven and device-profile dependent. |
| Replay active messages | `2` replayed messages | `replay_attack.py` | Vary replay intensity and timing. |
| Random seed | `42` in initial main flow engine only | `main.py`, `event_generator.py` | Make seed config-driven for reproducible dataset releases. |
| Scenario set | Normal flow and replay attack | `main.py`, `src/scenarios/` | Add scenario registry/config so new attacks can be enabled without editing `main.py`. |

## Recommended Refactoring Priorities

1. Centralize hard-coded values in `config/settings.yaml`.
2. Add a configuration loader and pass settings into `EventGenerator`, `MQTTBroker`, scenarios, and exporters.
3. Replace random anomaly flags with deterministic checks where possible, especially topic-scope violations and replay-window violations.
4. Add tests that assert exported CSV headers match `Event` fields and the documented feature set.
5. Keep `hash_method` explicit in every exported event so future datasets remain self-describing if the hash function changes.

