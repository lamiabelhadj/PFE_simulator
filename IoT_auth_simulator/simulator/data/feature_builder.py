"""
data/feature_builder.py
────────────────────────
Merges the per-step event dicts produced by the flow modules into a
single flat row ready for the dataset.

Each step returns keys like "step", "step_latency_ms", "step_success"
alongside its feature payload.  This module:
  1. Renames step-metadata keys to be step-prefixed (e.g. discovery_latency_ms)
  2. Merges all step dicts — later steps win on key conflicts for feature columns
  3. Adds a session_id for traceability
  4. Enforces the canonical column order 
"""

import uuid
from typing import List, Dict, Any

# Step name → prefix used for metadata keys
_STEP_PREFIXES = {
    "discovery":     "s1",
    "pairing":       "s2",
    "enrollment":    "s3",
    "authorization": "s4",
    "mqtt_session":  "s5",
    "reauth":        "s6",
}

# Metadata keys that should be renamed rather than kept as-is
_META_KEYS = {"step", "step_latency_ms", "step_success"}

# Final canonical column order 
COLUMN_ORDER = [
    # Identity & Discovery
    "session_id", "device_id", "claimed_device_id", "source_ip", "gateway_id",
    "registered_device", "source_connection_count", "source_diversity", "battery_level",
    # Network / Pairing
    "tcp_flags", "connection_duration", "tcp_rtt", "packet_rate",
    "inter_arrival_time", "frame_length", "tcp_segment_len",
    "pairing_result", "pairing_latency_ms",
    # Enrollment & Auth
    "credential_status", "mqtt_msg_type", "connect_flags", "clean_session",
    "username_present", "password_length", "keep_alive", "mqtt_version",
    "connack_code", "auth_result", "auth_latency_ms", "failed_auth_count",
    # Authorization
    "requested_topic", "topic_length", "operation", "requested_qos",
    "granted_qos", "authorization_result", "topic_scope_violation", "retain_flag",
    # MQTT Session
    "message_id", "duplicate_flag", "payload_length", "payload_hash",
    "qos_level", "message_rate", "byte_rate", "session_duration",
    # Continuous Re-auth
    "trust_score", "re_auth_required", "gateway_decision", "session_present",
    "source_ip_change", "replay_window_violation", "behavior_deviation_score",
    # Step latencies (diagnostics)
    "s1_latency_ms", "s2_latency_ms", "s3_latency_ms",
    "s4_latency_ms", "s5_latency_ms", "s6_latency_ms",
    # Labels
    "is_anomaly", "attack_type", "attack_phase", "severity",
]


def build(step_events: List[Dict[str, Any]], session_id: str = None) -> Dict[str, Any]:
    """
    Merge a list of per-step event dicts into one flat dataset row.

    Parameters
    ----------
    step_events : list of dicts returned by each flow step's run()
    session_id  : optional override; auto-generated if None

    Returns
    -------
    dict — one flat row with all features in canonical order
    """
    merged: Dict[str, Any] = {}
    step_meta: Dict[str, Any] = {}

    for event in step_events:
        step_name = event.get("step", "unknown")
        prefix    = _STEP_PREFIXES.get(step_name, step_name)

        for key, value in event.items():
            if key in _META_KEYS:
                if key == "step_latency_ms":
                    step_meta[f"{prefix}_latency_ms"] = value
                # "step" and "step_success" are dropped from the final row
            else:
                merged[key] = value   # later steps overwrite on conflict

    merged.update(step_meta)
    merged["session_id"] = session_id or str(uuid.uuid4())

    # Reorder according to canonical column list; unknown keys go at the end
    ordered: Dict[str, Any] = {}
    for col in COLUMN_ORDER:
        ordered[col] = merged.get(col, None)

    # Append any extra keys not in COLUMN_ORDER (e.g. token_age_s, dos_blocked_count)
    for k, v in merged.items():
        if k not in ordered:
            ordered[k] = v

    return ordered