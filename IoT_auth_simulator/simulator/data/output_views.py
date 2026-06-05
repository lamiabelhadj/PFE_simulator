"""
data/output_views.py
─────────────────────
Layer 3 of 3 — Output Views

Responsibility: export correlated event sequences in three formats.

  1. JSON event log   — one JSON object per sequence (list of event dicts).
                        Preserves full event-level detail for forensic analysis.

  2. Event CSV        — one row per event, all AuthEvent attributes as columns.
                        Suitable for sequence-aware models (LSTM, Transformers).

  3. Feature table    — one row per session (scenario), aggregated features.
                        Suitable for tabular ML models (Random Forest, XGBoost).
                        This is the format used by the Phase 0 ML pipeline.

Public API
──────────
  OutputViews.save(sequences, output_dir)
    → writes all three formats and returns the file paths.

  Individual helpers (also importable standalone):
    to_json_log(sequences)   → str  (JSON)
    to_event_df(sequences)   → pd.DataFrame  (one row per event)
    to_feature_df(sequences) → pd.DataFrame  (one row per session)
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from simulator.event_model import AuthEvent, EventType, AuthState


# ══════════════════════════════════════════════════════════════════════════════
# Format 1 — JSON event log
# ══════════════════════════════════════════════════════════════════════════════

def to_json_log(sequences: List[List[AuthEvent]]) -> str:
    """
    Serialise all event sequences to a JSON string.

    Output structure:
    [
      {
        "scenario_id": "...",
        "scenario_type": "normal" | anomaly_label,
        "event_count": N,
        "events": [ {event dict}, ... ]
      },
      ...
    ]
    """
    result = []
    for seq in sequences:
        if not seq:
            continue
        first = seq[0]
        anomaly_labels = {e.anomaly_label for e in seq if e.anomaly_label}
        result.append({
            "scenario_id":   first.scenario_id,
            "scenario_type": next(iter(anomaly_labels), "normal"),
            "event_count":   len(seq),
            "events":        [e.to_dict() for e in seq],
        })
    return json.dumps(result, indent=2, default=str)


# ══════════════════════════════════════════════════════════════════════════════
# Format 2 — Event-level CSV (one row per event)
# ══════════════════════════════════════════════════════════════════════════════

def to_event_df(sequences: List[List[AuthEvent]]) -> pd.DataFrame:
    """
    Flatten all events across all sequences into a single DataFrame.
    One row = one AuthEvent.  All 26 to_dict() keys become columns.
    """
    rows = [event.to_dict() for seq in sequences for event in seq]
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)

    # Enforce column order — identifiers first, then state, then payload
    ordered = [
        "event_id", "event_type", "timestamp", "delay_since_previous_event",
        "scenario_id", "session_id",
        "device_id", "gateway_id", "auth_server_id", "broker_id",
        "previous_state", "new_state",
        "result", "failure_reason", "retry_count",
        "token_id", "token_expiry", "token_scope",
        "nonce", "identity_claim",
        "client_id", "topic", "resource_id",
        "firmware_version", "source_context",
        "anomaly_label",
    ]
    extra = [c for c in df.columns if c not in ordered]
    df = df[ordered + extra]
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Format 3 — Session-level feature table (one row per scenario)
# ══════════════════════════════════════════════════════════════════════════════

def to_feature_df(sequences: List[List[AuthEvent]]) -> pd.DataFrame:
    """
    Aggregate each event sequence into one flat feature row.

    Features extracted
    ──────────────────
    Identity
      scenario_id, session_id, device_id, gateway_id

    Temporal
      session_duration_s      total time from first to last event
      mean_delay_s            average delay between consecutive events
      max_delay_s             maximum single delay (timeout / renewal signal)
      min_delay_s             minimum single delay (flood signal)

    Event type counts
      n_events                total events in sequence
      n_{event_type}          count of each of the 21 EventTypes

    State coverage
      visited_states          number of distinct states visited
      reached_session_open    bool — did session actually open?
      reached_access_granted  bool — did access actually succeed?

    Failure signals
      n_failures              count of FAILURE result events
      n_retries               max retry_count seen in sequence
      failure_rate            n_failures / n_events

    Token & identity
      n_token_reuses          times token_id reused across events (replay signal)
      n_nonce_reuses          times nonce reused (nonce reuse signal)
      identity_mismatch       bool — any event has identity_claim ≠ device_id
      n_state_jumps           times previous_state and expected state diverge

    Labels
      is_anomaly              1 if any event is labelled, else 0
      anomaly_type            the anomaly label (or "normal")
      anomaly_phase           event_type of the injected anomalous event
    """
    rows = []
    for seq in sequences:
        if not seq:
            continue
        row = _aggregate_sequence(seq)
        rows.append(row)
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _aggregate_sequence(seq: List[AuthEvent]) -> Dict:
    """Aggregate one sequence into a feature dict."""
    first = seq[0]
    last  = seq[-1]

    # ── Identity ──────────────────────────────────────────────────────────────
    row: Dict = {
        "scenario_id": first.scenario_id,
        "session_id":  first.session_id,
        "device_id":   first.device_id,
        "gateway_id":  first.gateway_id,
    }

    # ── Temporal ──────────────────────────────────────────────────────────────
    delays = [e.delay_since_previous_event for e in seq]
    row["session_duration_s"] = round(last.timestamp - first.timestamp, 4)
    row["mean_delay_s"]       = round(sum(delays) / len(delays), 4) if delays else 0.0
    row["max_delay_s"]        = round(max(delays), 4) if delays else 0.0
    row["min_delay_s"]        = round(min(d for d in delays if d > 0), 4) if any(d > 0 for d in delays) else 0.0

    # ── Event type counts ─────────────────────────────────────────────────────
    type_counts: Dict[str, int] = {et.value: 0 for et in EventType}
    for e in seq:
        type_counts[e.event_type.value] += 1
    row["n_events"] = len(seq)
    for et_val, count in type_counts.items():
        row[f"n_{et_val}"] = count

    # ── State coverage ────────────────────────────────────────────────────────
    visited = {e.new_state for e in seq}
    row["visited_states"]         = len(visited)
    row["reached_session_open"]   = int(AuthState.SESSION_OPEN   in visited)
    row["reached_access_granted"] = int(AuthState.ACCESS_GRANTED in visited)
    row["reached_authenticated"]  = int(AuthState.AUTHENTICATED  in visited)

    # ── Failure signals ───────────────────────────────────────────────────────
    from simulator.event_model import EventResult
    failures    = [e for e in seq if e.result == EventResult.FAILURE]
    row["n_failures"]    = len(failures)
    row["n_retries"]     = max((e.retry_count for e in seq), default=0)
    row["failure_rate"]  = round(len(failures) / len(seq), 4)

    # ── Token & identity ──────────────────────────────────────────────────────
    token_ids = [e.token_id for e in seq if e.token_id]
    nonces    = [e.nonce    for e in seq if e.nonce]
    row["n_token_reuses"]   = max(0, len(token_ids) - len(set(token_ids)))
    row["n_nonce_reuses"]   = max(0, len(nonces)    - len(set(nonces)))
    row["identity_mismatch"] = int(
        any(e.identity_claim and e.identity_claim != e.device_id for e in seq)
    )

    # State jump: an event's previous_state doesn't match the previous event's new_state
    jumps = 0
    for i in range(1, len(seq)):
        if seq[i].previous_state != seq[i - 1].new_state:
            jumps += 1
    row["n_state_jumps"] = jumps

    # ── Labels ────────────────────────────────────────────────────────────────
    anomaly_events = [e for e in seq if e.anomaly_label]
    row["is_anomaly"]    = int(bool(anomaly_events))
    row["anomaly_type"]  = anomaly_events[0].anomaly_label if anomaly_events else "normal"
    row["anomaly_phase"] = anomaly_events[0].event_type.value if anomaly_events else "none"

    return row


# ══════════════════════════════════════════════════════════════════════════════
# OutputViews — convenience wrapper that saves all three formats
# ══════════════════════════════════════════════════════════════════════════════

class OutputViews:
    """Save all three output formats to a directory."""

    def __init__(self, output_dir: str = "data/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        sequences:   List[List[AuthEvent]],
        stem:        str = "iot_auth",
        save_json:   bool = True,
        save_events: bool = True,
        save_features: bool = True,
    ) -> Dict[str, Path]:
        """
        Save event sequences in all requested formats.

        Returns a dict of format_name → file_path.
        """
        paths: Dict[str, Path] = {}

        if save_json:
            p = self.output_dir / f"{stem}_events.json"
            p.write_text(to_json_log(sequences), encoding="utf-8")
            paths["json"] = p
            print(f"  JSON log    → {p}  ({len(sequences):,} sequences)")

        if save_events:
            p   = self.output_dir / f"{stem}_event_log.csv"
            df  = to_event_df(sequences)
            df.to_csv(p, index=False)
            paths["event_csv"] = p
            print(f"  Event CSV   → {p}  ({len(df):,} rows × {len(df.columns)} cols)")

        if save_features:
            p   = self.output_dir / f"{stem}_features.csv"
            df  = to_feature_df(sequences)
            df.to_csv(p, index=False)
            paths["feature_csv"] = p
            print(f"  Feature CSV → {p}  ({len(df):,} rows × {len(df.columns)} cols)")

        return paths