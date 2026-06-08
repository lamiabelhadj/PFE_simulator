"""
data/output_views.py
─────────────────────
Layer 3 of 3 — Output Views

Exports correlated event sequences in three formats:

  1. JSON event log   — one JSON object per sequence (full event-level detail)
  2. Event CSV        — one row per AuthEvent (sequence-aware models)
  3. Feature CSV      — one row per session, all Phase 0 + Phase 2 features merged

"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import pandas as pd

from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.engines.event_engine import SessionContext

# Type alias for the two accepted input formats
SequenceInput = Union[
    List[Tuple[List[AuthEvent], SessionContext]],
    List[List[AuthEvent]],
]


def _normalise(sequences: SequenceInput) -> List[Tuple[List[AuthEvent], Optional[SessionContext]]]:
    """Normalise both input formats to List[(events, context|None)]."""
    if not sequences:
        return []
    first = sequences[0]
    if isinstance(first, tuple):
        return sequences          # type: ignore[return-value]
    return [(seq, None) for seq in sequences]


# ══════════════════════════════════════════════════════════════════════════════
# Format 1 — JSON event log
# ══════════════════════════════════════════════════════════════════════════════

def to_json_log(sequences: SequenceInput) -> str:
    pairs  = _normalise(sequences)
    result = []
    for events, ctx in pairs:
        if not events:
            continue
        first         = events[0]
        anomaly_lbls  = {e.anomaly_label for e in events if e.anomaly_label}
        scenario_type = next(iter(anomaly_lbls), "normal")
        entry: Dict = {
            "scenario_id":   first.scenario_id,
            "scenario_type": scenario_type,
            "event_count":   len(events),
            "events":        [e.to_dict() for e in events],
        }
        if ctx:
            entry["session_context"] = ctx.to_dict()
        result.append(entry)
    return json.dumps(result, indent=2, default=str)


# ══════════════════════════════════════════════════════════════════════════════
# Format 2 — Event-level CSV (one row per event)
# ══════════════════════════════════════════════════════════════════════════════

def to_event_df(sequences: SequenceInput) -> pd.DataFrame:
    """One row per AuthEvent. All 26 to_dict() keys become columns."""
    pairs = _normalise(sequences)
    rows  = [event.to_dict() for events, _ in pairs for event in events]
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    ordered = [
        "event_id", "event_type", "timestamp", "delay_since_previous_event",
        "scenario_id", "session_id",
        "device_id", "gateway_id", "auth_server_id", "broker_id",
        "previous_state", "new_state",
        "result", "failure_reason", "retry_count",
        "token_id", "token_expiry", "token_scope",
        "nonce", "identity_claim",
        "client_id", "topic", "resource_id",
        "firmware_version", "source_context", "anomaly_label",
    ]
    extra = [c for c in df.columns if c not in ordered]
    return df[[c for c in ordered if c in df.columns] + extra]


# ══════════════════════════════════════════════════════════════════════════════
# Format 3 — Session feature table (one row per session)
# ══════════════════════════════════════════════════════════════════════════════

def to_feature_df(sequences: SequenceInput) -> pd.DataFrame:
    """
    One row per session.

    Merges Phase 2 aggregate features (from AuthEvent sequence) with all
    Phase 0 features (from SessionContext) into a single flat row.

    Column groups
    ─────────────
    Phase 0 identity          : device_id, claimed_device_id, source_ip, …
    Phase 0 network/pairing   : tcp_rtt, packet_rate, pairing_latency_ms, …
    Phase 0 enrollment/auth   : credential_status, connack_code, auth_latency_ms, …
    Phase 0 authorization     : requested_topic, granted_qos, …
    Phase 0 MQTT session      : message_rate, byte_rate, session_duration, …
    Phase 0 re-auth           : trust_score, behavior_deviation_score, …
    Phase 0 step latencies    : s1_latency_ms … s6_latency_ms
    Phase 0 labels            : is_anomaly, attack_type, attack_phase, severity
    Phase 2 temporal          : session_duration_s, mean_delay_s, …
    Phase 2 event counts      : n_events, n_authentication_success, …
    Phase 2 state coverage    : visited_states, reached_session_open, …
    Phase 2 anomaly signals   : n_token_reuses, n_nonce_reuses, n_state_jumps, …
    """
    pairs = _normalise(sequences)
    rows  = [_build_row(events, ctx) for events, ctx in pairs if events]
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _build_row(
    events: List[AuthEvent],
    ctx:    Optional[SessionContext],
) -> Dict:
    first = events[0]
    last  = events[-1]
    row: Dict = {}

    # ── Phase 2: identifiers ──────────────────────────────────────────────────
    row["scenario_id"] = first.scenario_id
    row["session_id"]  = first.session_id
    row["device_id"]   = first.device_id
    row["gateway_id"]  = first.gateway_id

    # ── Phase 0: identity & discovery (from SessionContext or events) ─────────
    if ctx:
        row["claimed_device_id"]       = ctx.claimed_device_id
        row["source_ip"]               = ctx.source_ip
        row["registered_device"]       = ctx.registered_device
        row["source_connection_count"] = ctx.source_connection_count
        row["source_diversity"]        = ctx.source_diversity
        row["battery_level"]           = ctx.battery_level
    else:
        anomaly_evs = [e for e in events if e.anomaly_label and e.identity_claim]
        row["claimed_device_id"] = anomaly_evs[0].identity_claim if anomaly_evs else first.device_id
        row["source_ip"]               = None
        row["registered_device"]       = None
        row["source_connection_count"] = None
        row["source_diversity"]        = None
        row["battery_level"]           = None

    # ── Phase 0: network / pairing ────────────────────────────────────────────
    if ctx:
        row["tcp_flags"]           = ctx.tcp_flags
        row["connection_duration"] = ctx.connection_duration
        row["tcp_rtt"]             = ctx.tcp_rtt
        row["packet_rate"]         = ctx.packet_rate
        row["inter_arrival_time"]  = ctx.inter_arrival_time
        row["frame_length"]        = ctx.frame_length
        row["tcp_segment_len"]     = ctx.tcp_segment_len
        row["pairing_result"]      = ctx.pairing_result
        row["pairing_latency_ms"]  = ctx.pairing_latency_ms

    # ── Phase 0: enrollment & auth ────────────────────────────────────────────
    if ctx:
        row["credential_status"]  = ctx.credential_status
        row["mqtt_msg_type"]      = ctx.mqtt_msg_type
        row["connect_flags"]      = ctx.connect_flags
        row["clean_session"]      = ctx.clean_session
        row["username_present"]   = ctx.username_present
        row["password_length"]    = ctx.password_length
        row["keep_alive"]         = ctx.keep_alive
        row["mqtt_version"]       = ctx.mqtt_version
        row["connack_code"]       = ctx.connack_code
        row["auth_result"]        = ctx.auth_result
        row["auth_latency_ms"]    = ctx.auth_latency_ms
        row["failed_auth_count"]  = ctx.failed_auth_count

    # ── Phase 0: authorization ────────────────────────────────────────────────
    if ctx:
        row["requested_topic"]       = ctx.requested_topic
        row["topic_length"]          = ctx.topic_length
        row["operation"]             = ctx.operation
        row["requested_qos"]         = ctx.requested_qos
        row["granted_qos"]           = ctx.granted_qos
        row["authorization_result"]  = ctx.authorization_result
        row["topic_scope_violation"] = ctx.topic_scope_violation
        row["retain_flag"]           = ctx.retain_flag

    # ── Phase 0: MQTT session ─────────────────────────────────────────────────
    if ctx:
        row["message_id"]      = ctx.message_id
        row["duplicate_flag"]  = ctx.duplicate_flag
        row["payload_length"]  = ctx.payload_length
        row["payload_hash"]    = ctx.payload_hash
        row["qos_level"]       = ctx.qos_level
        row["message_rate"]    = ctx.message_rate
        row["byte_rate"]       = ctx.byte_rate
        row["session_duration"] = ctx.session_duration

    # ── Phase 0: continuous re-auth ───────────────────────────────────────────
    if ctx:
        row["trust_score"]               = ctx.trust_score
        row["re_auth_required"]          = ctx.re_auth_required
        row["gateway_decision"]          = ctx.gateway_decision
        row["session_present"]           = ctx.session_present
        row["source_ip_change"]          = ctx.source_ip_change
        row["replay_window_violation"]   = ctx.replay_window_violation
        row["behavior_deviation_score"]  = ctx.behavior_deviation_score

    # ── Phase 0: step latencies ───────────────────────────────────────────────
    if ctx:
        row["s1_latency_ms"] = ctx.s1_latency_ms
        row["s2_latency_ms"] = ctx.s2_latency_ms
        row["s3_latency_ms"] = ctx.s3_latency_ms
        row["s4_latency_ms"] = ctx.s4_latency_ms
        row["s5_latency_ms"] = ctx.s5_latency_ms
        row["s6_latency_ms"] = ctx.s6_latency_ms

    # ── Phase 2: temporal ─────────────────────────────────────────────────────
    delays = [e.delay_since_previous_event for e in events]
    row["session_duration_s"] = round(last.timestamp - first.timestamp, 4)
    row["mean_delay_s"]       = round(sum(delays) / len(delays), 4) if delays else 0.0
    row["max_delay_s"]        = round(max(delays), 4) if delays else 0.0
    row["min_delay_s"]        = round(min(d for d in delays if d > 0), 4) \
                                if any(d > 0 for d in delays) else 0.0

    # ── Phase 2: event type counts ────────────────────────────────────────────
    type_counts = {et.value: 0 for et in EventType}
    for e in events:
        type_counts[e.event_type.value] += 1
    row["n_events"] = len(events)
    for et_val, count in type_counts.items():
        row[f"n_{et_val}"] = count

    # ── Phase 2: state coverage ───────────────────────────────────────────────
    visited = {e.new_state for e in events}
    row["visited_states"]         = len(visited)
    row["reached_session_open"]   = int(AuthState.SESSION_OPEN   in visited)
    row["reached_access_granted"] = int(AuthState.ACCESS_GRANTED in visited)
    row["reached_authenticated"]  = int(AuthState.AUTHENTICATED  in visited)

    # ── Phase 2: failure signals ──────────────────────────────────────────────
    failures = [e for e in events if e.result == EventResult.FAILURE]
    row["n_failures"]   = len(failures)
    row["n_retries"]    = max((e.retry_count for e in events), default=0)
    row["failure_rate"] = round(len(failures) / len(events), 4)

    # ── Phase 2: token / identity signals ─────────────────────────────────────
    token_ids = [e.token_id for e in events if e.token_id]
    nonces    = [e.nonce    for e in events if e.nonce]
    row["n_token_reuses"]    = max(0, len(token_ids) - len(set(token_ids)))
    row["n_nonce_reuses"]    = max(0, len(nonces)    - len(set(nonces)))
    row["identity_mismatch"] = int(
        any(e.identity_claim and e.identity_claim != e.device_id for e in events)
    )
    jumps = sum(
        1 for i in range(1, len(events))
        if events[i].previous_state != events[i - 1].new_state
    )
    row["n_state_jumps"] = jumps

    # ── Labels (Phase 0 naming + Phase 2 additions) ───────────────────────────
    anomaly_events = [e for e in events if e.anomaly_label]
    row["is_anomaly"]   = int(bool(anomaly_events))
    row["attack_type"]  = ctx.attack_type  if ctx else (anomaly_events[0].anomaly_label if anomaly_events else "normal")
    row["attack_phase"] = ctx.attack_phase if ctx else (anomaly_events[0].event_type.value if anomaly_events else "none")
    row["severity"]     = ctx.severity     if ctx else "none"
    row["anomaly_type"] = row["attack_type"]   # Phase 2 alias
    row["anomaly_phase"] = row["attack_phase"]  # Phase 2 alias

    return row


# ══════════════════════════════════════════════════════════════════════════════
# OutputViews — save all three formats
# ══════════════════════════════════════════════════════════════════════════════

class OutputViews:
    def __init__(self, output_dir: str = "data/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        sequences:     SequenceInput,
        stem:          str  = "iot_auth",
        save_json:     bool = True,
        save_events:   bool = True,
        save_features: bool = True,
    ) -> Dict[str, Path]:
        paths: Dict[str, Path] = {}

        if save_json:
            p = self.output_dir / f"{stem}_events.json"
            p.write_text(to_json_log(sequences), encoding="utf-8")
            n = len(_normalise(sequences))
            paths["json"] = p
            print(f"  JSON log    → {p}  ({n:,} sequences)")

        if save_events:
            p  = self.output_dir / f"{stem}_event_log.csv"
            df = to_event_df(sequences)
            df.to_csv(p, index=False)
            paths["event_csv"] = p
            print(f"  Event CSV   → {p}  ({len(df):,} rows × {len(df.columns)} cols)")

        if save_features:
            p  = self.output_dir / f"{stem}_features.csv"
            df = to_feature_df(sequences)
            df.to_csv(p, index=False)
            paths["feature_csv"] = p
            print(f"  Feature CSV → {p}  ({len(df):,} rows × {len(df.columns)} cols)")

        return paths