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


def _print(msg: str) -> None:
    """Print with ASCII fallback — safe on Windows cp1252 consoles."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"))

from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.engines.event_engine import SessionContext, SEVERITY_MAP

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
        scenario_type = (
            getattr(ctx, "attack_type", "normal")
            if ctx else next(iter(anomaly_lbls), "normal")
        )
        entry: Dict = {
            "scenario_id":   first.scenario_id,
            "trace_id":      first.trace_id,
            "legacy_session_id": first.session_id,
            "protected_session_id": (
                getattr(ctx, "protected_session_id", None)
                if ctx else next(
                    (event.protected_session_id for event in events
                     if event.protected_session_id),
                    None,
                )
            ),
            "scenario_type": scenario_type,
            "event_count":   len(events),
            "generation_profile": getattr(ctx, "generation_profile", None) if ctx else None,
            "attack_scenario_intent": (
                getattr(ctx, "attack_scenario_intent", False) if ctx else False
            ),
            "observable_anomaly": (
                getattr(ctx, "observable_anomaly", bool(anomaly_lbls))
                if ctx else bool(anomaly_lbls)
            ),
            "injection_records": getattr(ctx, "injection_records", ()) if ctx else (),
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
    """
    One row per AuthEvent.

    The `timestamp` column is rendered as a human-readable UTC datetime string
    with microseconds, and each row carries the
    session-level `attack_type` label so the per-event log is self-describing
    and filterable.
    """
    pairs = _normalise(sequences)
    rows  = []
    for events, ctx in pairs:
        if not events:
            continue
        if ctx:
            attack_type = getattr(ctx, "attack_type", "normal")
        else:
            lbls = [e.anomaly_label for e in events if getattr(e, "anomaly_label", None)]
            attack_type = lbls[0] if lbls else "normal"
        for event in events:
            d = event.to_dict()
            d["attack_type"] = attack_type
            d["generation_profile"] = getattr(ctx, "generation_profile", None) if ctx else None
            d["attack_scenario_intent"] = (
                getattr(ctx, "attack_scenario_intent", False) if ctx else False
            )
            d["observable_anomaly"] = (
                getattr(ctx, "observable_anomaly", bool(event.anomaly_label))
                if ctx else bool(event.anomaly_label)
            )
            rows.append(d)
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    # Render the semantic timestamp using its Unix-compatible coordinate:
    # full date + time, e.g. "2026-06-23 14:30:05".
    df["timestamp"] = (
        pd.to_datetime(df["timestamp"], unit="s")
          .dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    )
    if "observed_timestamp" in df.columns:
        observed_dt = pd.to_datetime(
            df["observed_timestamp"], unit="s", errors="coerce"
        )
        df["observed_timestamp"] = (
            observed_dt.dt.strftime("%Y-%m-%d %H:%M:%S.%f")
            .where(observed_dt.notna(), None)
        )
    # token_expiry is also a Unix timestamp — render it the same way, leaving
    # rows without a token blank rather than showing "NaT".
    if "token_expiry" in df.columns:
        expiry_dt = pd.to_datetime(df["token_expiry"], unit="s", errors="coerce")
        df["token_expiry"] = (
            expiry_dt.dt.strftime("%Y-%m-%d %H:%M:%S").where(expiry_dt.notna(), None)
        )
    ordered = [
        "event_id", "event_type", "timestamp", "observed_timestamp",
        "observed_timestamp_source", "targeted_temporal_relationship",
        "injection_id", "anomaly_variant_name", "invariant_families",
        "delay_since_previous_event",
        "scenario_id", "trace_id", "session_id",
        "auth_attempt_id", "protected_session_id", "access_request_id",
        "device_id", "gateway_id", "auth_server_id", "broker_id",
        "previous_state", "new_state",
        "result", "failure_reason", "retry_count",
        "token_id", "token_expiry", "token_scope",
        "nonce", "identity_claim",
        "topic", "resource_id", "requested_action",
        "authenticated_identity", "token_validation_result",
        "authorization_decision", "resource_operation_outcome",
        "authenticated_context_active", "token_context_active",
        "protected_session_active",
        "firmware_version", "source_context", "anomaly_label", "attack_type",
        "generation_profile", "attack_scenario_intent", "observable_anomaly",
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
    row: Dict = {}

    # ── Phase 2: identifiers ──────────────────────────────────────────────────
    row["scenario_id"] = first.scenario_id
    row["trace_id"]    = first.trace_id
    # Historical trace-grouping field retained as a compatibility identifier.
    row["session_id"]  = first.session_id
    row["protected_session_id"] = (
        getattr(ctx, "protected_session_id", None)
        if ctx else next(
            (event.protected_session_id for event in events
             if event.protected_session_id),
            None,
        )
    )
    row["auth_attempt_count"] = len({
        event.auth_attempt_id for event in events if event.auth_attempt_id
    })
    row["device_id"]   = first.device_id
    row["gateway_id"]  = first.gateway_id

    # ── Phase 0: identity & discovery (from SessionContext or events) ─────────
    if ctx:
        row["claimed_device_id"]       = getattr(ctx, "claimed_device_id", first.device_id)
        row["source_ip"]               = getattr(ctx, "source_ip", None)
        row["registered_device"]       = getattr(ctx, "registered_device", None)
        row["source_connection_count"] = getattr(ctx, "source_connection_count", None)
        row["battery_level"]           = getattr(ctx, "battery_level", None)
    else:
        identity_evs = [e for e in events if getattr(e, "identity_claim", None)]
        row["claimed_device_id"] = identity_evs[0].identity_claim if identity_evs else first.device_id
        row["source_ip"]               = None
        row["registered_device"]       = None
        row["source_connection_count"] = None
        row["battery_level"]           = None

    # ── Phase 0: network / pairing ────────────────────────────────────────────
    if ctx:
        row["tcp_flags"]           = getattr(ctx, "tcp_flags", None)
        row["connection_duration"] = getattr(ctx, "connection_duration", None)
        row["tcp_rtt"]             = getattr(ctx, "tcp_rtt", None)
        row["packet_rate"]         = getattr(ctx, "packet_rate", None)
        row["inter_arrival_time"]  = getattr(ctx, "inter_arrival_time", None)
        row["frame_length"]        = getattr(ctx, "frame_length", None)
        row["tcp_segment_len"]     = getattr(ctx, "tcp_segment_len", None)
        row["pairing_result"]      = getattr(ctx, "pairing_result", None)
        row["pairing_latency_ms"]  = getattr(ctx, "pairing_latency_ms", None)

    # ── Phase 0: enrollment & auth ────────────────────────────────────────────
    if ctx:
        row["mqtt_msg_type"]      = getattr(ctx, "mqtt_msg_type", None)
        row["connect_flags"]      = getattr(ctx, "connect_flags", None)
        row["clean_session"]      = getattr(ctx, "clean_session", None)
        row["username_present"]   = getattr(ctx, "username_present", None)
        row["password_length"]    = getattr(ctx, "password_length", None)
        row["keep_alive"]         = getattr(ctx, "keep_alive", None)
        row["mqtt_version"]       = getattr(ctx, "mqtt_version", None)
        row["connack_code"]       = getattr(ctx, "connack_code", None)
        row["auth_result"]        = getattr(ctx, "auth_result", None)
        row["auth_latency_ms"]    = getattr(ctx, "auth_latency_ms", None)
        row["failed_auth_count"]  = getattr(ctx, "failed_auth_count", None)
        row["authentication_result_semantic"] = getattr(
            ctx, "authentication_result_semantic", "not_evaluated"
        )
        row["last_authentication_attempt_result"] = getattr(
            ctx, "last_authentication_attempt_result", "not_evaluated"
        )
        row["authenticated_identity"] = getattr(ctx, "authenticated_identity", None)
        row["authenticated_context_active"] = getattr(
            ctx, "authenticated_context_active", False
        )
        row["token_validation_result"] = getattr(
            ctx, "token_validation_result", "not_evaluated"
        )
        row["token_context_active"] = getattr(ctx, "token_context_active", False)
        row["protected_session_active"] = getattr(
            ctx, "protected_session_active", False
        )
        row["semantic_time_domain"] = getattr(ctx, "semantic_time_domain", None)
        row["trace_started_at"] = getattr(ctx, "trace_started_at", None)
        row["trace_ended_at"] = getattr(ctx, "trace_ended_at", None)
        row["token_issued_at"] = getattr(ctx, "token_issued_at", None)
        row["token_presented_at"] = getattr(ctx, "token_presented_at", None)
        row["token_validation_at"] = getattr(ctx, "token_validation_at", None)
        row["token_validity_duration_s"] = getattr(
            ctx, "token_validity_duration_s", None
        )
        row["challenge_issued_at"] = getattr(ctx, "challenge_issued_at", None)
        row["challenge_response_at"] = getattr(ctx, "challenge_response_at", None)
        row["protected_session_started_at"] = getattr(
            ctx, "protected_session_started_at", None
        )
        row["protected_session_ended_at"] = getattr(
            ctx, "protected_session_ended_at", None
        )
        row["renewal_requested_at"] = getattr(ctx, "renewal_requested_at", None)
        row["renewed_token_issued_at"] = getattr(
            ctx, "renewed_token_issued_at", None
        )

    # ── Phase 0: authorization ────────────────────────────────────────────────
    if ctx:
        row["requested_topic"]       = getattr(ctx, "requested_topic", None)
        row["topic_length"]          = getattr(ctx, "topic_length", None)
        row["operation"]             = getattr(ctx, "operation", None)
        row["authorization_result"]  = getattr(ctx, "authorization_result", None)
        row["topic_scope_violation"] = getattr(ctx, "topic_scope_violation", None)
        row["retain_flag"]           = getattr(ctx, "retain_flag", None)
        row["requested_action"]      = getattr(ctx, "requested_action", None)
        row["authorization_decision"] = getattr(
            ctx, "authorization_decision", "not_evaluated"
        )
        row["resource_operation_outcome"] = getattr(
            ctx, "resource_operation_outcome", "not_executed"
        )
        row["access_request_count"] = len(
            getattr(ctx, "access_request_ids", ())
        )

    # ── Phase 0: MQTT session ─────────────────────────────────────────────────
    if ctx:
        row["message_id"]      = getattr(ctx, "message_id", None)
        row["duplicate_flag"]  = getattr(ctx, "duplicate_flag", None)
        row["payload_length"]  = getattr(ctx, "payload_length", None)
        row["payload_hash"]    = getattr(ctx, "payload_hash", None)
        row["qos_level"]       = getattr(ctx, "qos_level", None)
        row["message_rate"]    = getattr(ctx, "message_rate", None)
        row["byte_rate"]       = getattr(ctx, "byte_rate", None)

    # ── Phase 0: continuous re-auth ───────────────────────────────────────────
    if ctx:
        row["trust_score"]               = getattr(ctx, "trust_score", None)
        row["re_auth_required"]          = getattr(ctx, "re_auth_required", None)
        row["session_present"]           = getattr(ctx, "session_present", None)
        row["source_ip_change"]          = getattr(ctx, "source_ip_change", None)
        row["replay_window_violation"]   = getattr(ctx, "replay_window_violation", None)

    # ── Phase 0: step latencies ───────────────────────────────────────────────
    if ctx:
        row["s1_latency_ms"] = getattr(ctx, "s1_latency_ms", None)
        row["s2_latency_ms"] = getattr(ctx, "s2_latency_ms", None)
        row["s3_latency_ms"] = getattr(ctx, "s3_latency_ms", None)
        row["s4_latency_ms"] = getattr(ctx, "s4_latency_ms", None)
        row["s5_latency_ms"] = getattr(ctx, "s5_latency_ms", None)
        row["s6_latency_ms"] = getattr(ctx, "s6_latency_ms", None)

    # ── Phase 2: temporal ─────────────────────────────────────────────────────
    delays = [e.delay_since_previous_event for e in events]
    # Session duration uses authoritative semantic timestamps. Any separately
    # injected observed timestamp evidence cannot alter this value.
    row["session_duration_s"] = round(
        max(0.0, max(e.timestamp for e in events) - first.timestamp), 4
    )
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
    if ctx:
        row["is_anomaly"]   = int(getattr(ctx, "observable_anomaly", False))
        row["attack_type"]  = getattr(ctx, "attack_type", "normal")
        row["attack_phase"] = getattr(ctx, "attack_phase", "none")
        row["severity"]     = getattr(ctx, "severity", "none")
        row["attack_scenario_intent"] = int(
            getattr(ctx, "attack_scenario_intent", False)
        )
        row["observable_anomaly"] = int(
            getattr(ctx, "observable_anomaly", False)
        )
        row["observable_violation_candidate"] = int(
            getattr(ctx, "observable_violation_candidate", False)
        )
        row["generation_profile"] = getattr(ctx, "generation_profile", None)
        row["injection_count"] = len(getattr(ctx, "injection_records", ()))
    else:
        attack_evs = [e for e in events if getattr(e, "anomaly_label", None) or getattr(e, "source_context", "") == "attack"]
        row["is_anomaly"]   = int(bool(attack_evs))
        if attack_evs:
            row["attack_type"]  = attack_evs[0].anomaly_label if attack_evs[0].anomaly_label else "attack"
            row["attack_phase"] = attack_evs[0].event_type.value
            row["severity"]     = SEVERITY_MAP.get(attack_evs[0].anomaly_label, "medium") if attack_evs[0].anomaly_label else "medium"
        else:
            row["attack_type"]  = "normal"
            row["attack_phase"] = "none"
            row["severity"]     = "none"

    # ── Phase 4: replay variant signals ──────────────────────────────────────
    if ctx:
        row["token_age_at_replay"]     = getattr(ctx, "token_age_at_replay",     0.0)
        row["nonce_age_at_reuse"]      = getattr(ctx, "nonce_age_at_reuse",      0.0)
        row["timestamp_delta_s"]       = getattr(ctx, "timestamp_delta_s",       0.0)
        row["duplicate_session_count"] = getattr(ctx, "duplicate_session_count", 0)
    else:
        row["token_age_at_replay"]     = 0.0
        row["nonce_age_at_reuse"]      = 0.0
        row["timestamp_delta_s"]       = 0.0
        row["duplicate_session_count"] = 0

    # ── Phase 5: identity / session anomaly signals ───────────────────────────
    if ctx:
        row["identity_claim_mismatch"]     = getattr(ctx, "identity_claim_mismatch",     0)
        row["token_device_mismatch"]       = getattr(ctx, "token_device_mismatch",       0)
        row["unauthorized_access_attempt"] = getattr(ctx, "unauthorized_access_attempt", 0)
        row["steps_before_access"]         = getattr(ctx, "steps_before_access",         0)
    else:
        row["identity_claim_mismatch"]     = 0
        row["token_device_mismatch"]       = 0
        row["unauthorized_access_attempt"] = 0
        row["steps_before_access"]         = 0

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
            _print(f"  JSON log    -> {p}  ({n:,} sequences)")

        if save_events:
            p  = self.output_dir / f"{stem}_event_log.csv"
            df = to_event_df(sequences)
            df.to_csv(p, index=False)
            paths["event_csv"] = p
            _print(f"  Event CSV   -> {p}  ({len(df):,} rows x {len(df.columns)} cols)")

        if save_features:
            p  = self.output_dir / f"{stem}_features.csv"
            df = to_feature_df(sequences)
            df.to_csv(p, index=False)
            paths["feature_csv"] = p
            _print(f"  Feature CSV -> {p}  ({len(df):,} rows x {len(df.columns)} cols)")

        return paths
