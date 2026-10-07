"""Stage 3 — per-session features computed ONLY from detector-observable events.

Each feature carries a `group` and a plain-language description; both are
written to `feature_dictionary.csv` and reused by the report. Groups:

  structure   how long / how complex the session is (protocol shape)
  counts      how many times each event type occurs
  timing      inter-event delays and timestamp ordering
  nonce       challenge-nonce usage across authentication attempts
  token       token / resource / topic usage

`MECHANISM_FEATURES` lists the few features that directly encode how the two
anomaly types were injected; the separability stage compares models with and
without them to expose shortcut learning.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import DELAY_FLOOR, EVENT_ORDER, Paths

FEATURE_INFO: dict[str, tuple[str, str]] = {}


def _f(name: str, group: str, desc: str) -> str:
    FEATURE_INFO[name] = (group, desc)
    return name


MECHANISM_FEATURES = [
    "delay_min", "response_delay_min", "n_negative_delays",
    "n_nonces_reused_across_attempts", "attempts_minus_unique_nonces", "max_nonce_multiplicity",
    # proxies: carry the same signal in diluted form (found via the context-only tree)
    "response_sent_delay_mean", "n_unique_nonces",
]


def session_features(s: pd.DataFrame) -> dict:
    t = s["event_type"]
    d = s["observed_delay_since_previous_event"].to_numpy()
    gaps = d[1:]  # the first delay is always 0 by construction
    f: dict[str, float] = {}

    # structure
    f[_f("n_events", "structure", "number of events in the session")] = len(s)
    f[_f("n_attempts", "structure", "authentication handshakes (challenge_sent count)")] = int(s["attempt_index"].max())
    f[_f("n_failures", "structure", "authentication_failure events")] = int((s["result"] == "failure").sum())
    f[_f("max_retry_count", "structure", "highest retry_count reached")] = int(s["retry_count"].max())
    f[_f("has_enrollment", "structure", "session begins with discovery/pairing/enrollment")] = int((t == "discovery").any())
    f[_f("has_renewal", "structure", "session contains a token renewal")] = int((t == "renewal_request").any())
    f[_f("has_session_closed", "structure", "session explicitly closed")] = int((t == "session_closed").any())
    f[_f("ends_with", "structure", "event type of the last event (categorical, not modelled)")] = t.iloc[-1]

    # counts per event type
    vc = t.value_counts()
    for et in EVENT_ORDER:
        f[_f(f"count_{et}", "counts", f"number of '{et}' events")] = int(vc.get(et, 0))

    # timing
    f[_f("duration_s", "timing", "last timestamp − first timestamp (s)")] = float(s["observed_timestamp"].iloc[-1] - s["observed_timestamp"].iloc[0])
    f[_f("delay_mean", "timing", "mean inter-event delay (s)")] = float(gaps.mean())
    f[_f("delay_median", "timing", "median inter-event delay (s)")] = float(np.median(gaps))
    f[_f("delay_std", "timing", "std of inter-event delays (s)")] = float(gaps.std())
    f[_f("delay_max", "timing", "longest inter-event delay (s)")] = float(gaps.max())
    f[_f("delay_min", "timing", "shortest inter-event delay (s); negative = clock went backwards")] = float(gaps.min())
    f[_f("n_negative_delays", "timing", "events timestamped before their predecessor")] = int((gaps < 0).sum())
    f[_f("n_floor_delays", "timing", f"delays at the simulator floor (0 ≤ d ≤ {DELAY_FLOOR*1.5:.1e} s)")] = int(((gaps >= 0) & (gaps <= DELAY_FLOOR * 1.5)).sum())
    for et in ["challenge_sent", "nonce_received", "response_sent", "authentication_success", "token_issued", "access_granted"]:
        sel = d[(t == et).to_numpy()]
        f[_f(f"{et}_delay_mean", "timing", f"mean delay preceding '{et}' (s)")] = float(sel.mean()) if len(sel) else np.nan
    resp = d[(t == "response_sent").to_numpy()]
    f[_f("response_delay_min", "timing", "smallest nonce_received→response_sent gap (s) — the causal margin")] = float(resp.min())
    big = gaps[gaps < 10]
    f[_f("active_delay_mean", "timing", "mean delay excluding idle gaps ≥10 s (renewal waits)")] = float(big.mean()) if len(big) else np.nan

    # nonce
    n = s.loc[s["nonce"].notna(), ["nonce", "attempt_index"]]
    per_nonce_attempts = n.groupby("nonce")["attempt_index"].nunique()
    f[_f("n_nonce_events", "nonce", "events carrying a nonce")] = len(n)
    f[_f("n_unique_nonces", "nonce", "distinct nonces in the session")] = int(n["nonce"].nunique())
    f[_f("n_nonces_reused_across_attempts", "nonce", "nonces that appear in more than one handshake")] = int((per_nonce_attempts > 1).sum())
    f[_f("attempts_minus_unique_nonces", "nonce", "handshakes − distinct nonces (0 = every handshake fresh)")] = f["n_attempts"] - f["n_unique_nonces"]
    f[_f("max_nonce_multiplicity", "nonce", "most events sharing one nonce (3 = one handshake)")] = int(n["nonce"].value_counts().max())

    # token / access
    f[_f("n_unique_tokens", "token", "distinct token_ids")] = int(s["token_id"].nunique())
    f[_f("n_token_events", "token", "events carrying a token_id")] = int(s["token_id"].notna().sum())
    act = s.loc[t == "access_request", "requested_action"]
    f[_f("n_reads", "token", "access requests with action=read")] = int((act == "read").sum())
    f[_f("n_writes", "token", "access requests with action=write")] = int((act == "write").sum())
    f[_f("n_unique_resources", "token", "distinct resource_ids accessed")] = int(s["resource_id"].nunique())
    f[_f("n_unique_topics", "token", "distinct MQTT-like topics")] = int(s["topic"].nunique())
    return f


def run(paths: Paths, events: pd.DataFrame, samples: pd.DataFrame) -> pd.DataFrame:
    ev = events.sort_values(["sample_key", "event_index"])
    feats = pd.DataFrame(
        [{"sample_key": k, **session_features(s)} for k, s in ev.groupby("sample_key", sort=True)]
    )
    labels = samples[["sample_key", "device", "detector_truth", "role", "role_kind", "semantic_family"]]
    feats = labels.merge(feats, on="sample_key", how="left")
    feats.insert(2, "y", (feats.pop("detector_truth") == "anomaly").astype(int))
    feats.to_csv(paths.data / "features.csv", index=False, lineterminator="\n")

    pd.DataFrame(
        [{"feature": k, "group": g, "mechanism_feature": k in MECHANISM_FEATURES, "description": d}
         for k, (g, d) in FEATURE_INFO.items()]
    ).to_csv(paths.tables / "feature_dictionary.csv", index=False, lineterminator="\n")
    return feats


def numeric_feature_names(feats: pd.DataFrame) -> list[str]:
    return [c for c in FEATURE_INFO if c in feats.columns and pd.api.types.is_numeric_dtype(feats[c])]
