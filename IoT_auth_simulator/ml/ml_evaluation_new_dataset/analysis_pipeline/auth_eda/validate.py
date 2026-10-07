"""Stage 2 — integrity and consistency checks.

Each check returns PASS / WARN / FAIL with a human-readable detail, so the
report can state precisely what was verified about the data before any
analysis is trusted. Checks fall in four groups: file contract, event-level
consistency, protocol grammar, and metadata ↔ observation agreement.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import Paths
from .convert import EVENT_FIELDS, reload

TS_TOL = 1e-5  # seconds; float64 at ~1.7e9 s has ~2e-7 s resolution


def _check(rows, group, name, ok, detail, warn=False):
    status = "PASS" if ok else ("WARN" if warn else "FAIL")
    rows.append({"group": group, "check": name, "status": status, "detail": detail})


def run(paths: Paths, raw: dict, events: pd.DataFrame, samples: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    S = raw["samples"]

    # ---- file contract -------------------------------------------------
    _check(rows, "contract", "sample_count header matches samples",
           raw["sample_count"] == len(S), f"header={raw['sample_count']}, actual={len(S)}")
    _check(rows, "contract", "sample_id unique",
           samples["sample_id"].is_unique, f"{samples['sample_id'].nunique()} unique / {len(samples)}")
    missing = sum(1 for s in S for e in s["detector_observations"] if set(e) != set(EVENT_FIELDS))
    _check(rows, "contract", "every event has exactly the 11 schema fields",
           missing == 0, f"{missing} events with a different key set")
    meta_keys = {frozenset(s["privileged_metadata"]) for s in S}
    _check(rows, "contract", "every sample has the same metadata keys",
           len(meta_keys) == 1, f"{len(meta_keys)} distinct metadata key sets")
    ev2, sm2 = reload(paths)
    _check(rows, "contract", "CSV round-trip preserves shape",
           ev2.shape == events.shape and sm2.shape == samples.shape,
           f"events {ev2.shape}, samples {sm2.shape}")
    ts_rt = np.abs(ev2["observed_timestamp"].to_numpy() - events["observed_timestamp"].to_numpy()).max()
    _check(rows, "contract", "CSV round-trip preserves timestamps exactly",
           ts_rt == 0.0, f"max |Δ| = {ts_rt:.3g} s")

    # ---- event-level consistency ---------------------------------------
    ev = events.sort_values(["sample_key", "event_index"])
    g = ev.groupby("sample_key", sort=False)
    first = g.head(1)
    _check(rows, "events", "first event of each session has delay 0",
           (first["observed_delay_since_previous_event"] == 0).all(),
           f"{(first['observed_delay_since_previous_event'] != 0).sum()} sessions violate")
    diff = g["observed_timestamp"].diff()
    err = (diff - ev["observed_delay_since_previous_event"]).abs().dropna()
    _check(rows, "events", "delay == timestamp difference (|err| < 10 µs)",
           (err < TS_TOL).all(), f"max |err| = {err.max():.2e} s over {len(err)} gaps")
    neg = ev.loc[ev["observed_delay_since_previous_event"] < 0]
    neg_roles = neg["label_role"].value_counts().to_dict()
    _check(rows, "events", "negative delays occur only in anomaly:timestamp_inconsistency",
           set(neg_roles) <= {"anomaly:timestamp_inconsistency"},
           f"{len(neg)} negative delays; by role: {neg_roles}")
    normal_neg = ev.loc[(ev["label_detector_truth"] == "normal") & (ev["observed_delay_since_previous_event"] < 0)]
    _check(rows, "events", "timestamps are monotone in every normal session",
           normal_neg.empty, f"{normal_neg['sample_key'].nunique()} normal sessions non-monotone")
    fail = ev["result"] == "failure"
    _check(rows, "events", "result=failure ⇔ failure_reason set ⇔ authentication_failure",
           (fail == ev["failure_reason"].notna()).all() and (fail == (ev["event_type"] == "authentication_failure")).all(),
           f"{fail.sum()} failure events")
    mono_retry = g["retry_count"].apply(lambda s: s.is_monotonic_increasing).all()
    _check(rows, "events", "retry_count never decreases within a session", bool(mono_retry),
           f"values observed: {sorted(ev['retry_count'].unique().tolist())}")
    tok_types = {"token_issued", "token_presented", "token_validated"}
    tok_missing = ev.loc[ev["event_type"].isin(tok_types) & ev["token_id"].isna()]
    _check(rows, "events", "token events always carry token_id", tok_missing.empty, f"{len(tok_missing)} missing")
    acc = ev.loc[ev["event_type"] == "access_request"]
    _check(rows, "events", "access_request always carries resource_id + requested_action",
           acc["resource_id"].notna().all() and acc["requested_action"].notna().all(), f"{len(acc)} access requests")
    nonce_types = {"challenge_sent", "nonce_received", "response_sent"}
    nonce_bad = ev.loc[ev["event_type"].isin(nonce_types) != ev["nonce"].notna()]
    _check(rows, "events", "nonce present exactly on challenge/nonce_received/response_sent",
           nonce_bad.empty, f"{len(nonce_bad)} violations")

    # ---- protocol grammar -----------------------------------------------
    starts = first["event_type"].value_counts().to_dict()
    _check(rows, "grammar", "sessions start with authentication_request or discovery",
           set(starts) <= {"authentication_request", "discovery"}, f"start events: {starts}")
    bad_triplets = 0
    for _, s in g:
        types, nonces = s["event_type"].tolist(), s["nonce"].tolist()
        for k, t in enumerate(types):
            if t == "challenge_sent":
                ok = (types[k + 1:k + 3] == ["nonce_received", "response_sent"]
                      and nonces[k] == nonces[k + 1] == nonces[k + 2])
                bad_triplets += not ok
    _check(rows, "grammar", "challenge → nonce_received → response_sent share one nonce",
           bad_triplets == 0, f"{bad_triplets} malformed handshakes")
    after_acc = ev.assign(nxt=g["event_type"].shift(-1)).query("event_type == 'access_request'")
    _check(rows, "grammar", "every access_request is answered by access_granted",
           (after_acc["nxt"] == "access_granted").all(), f"next events: {after_acc['nxt'].value_counts().to_dict()}")

    # ---- metadata ↔ observations ----------------------------------------
    sm = samples.set_index("sample_key")
    obs_attempts = ev.groupby("sample_key")["attempt_index"].max()
    _check(rows, "metadata", "structure.authentication_attempt_count == observed handshakes",
           (obs_attempts == sm["structure.authentication_attempt_count"]).all(),
           f"{(obs_attempts != sm['structure.authentication_attempt_count']).sum()} mismatches")
    obs_access = ev.query("event_type == 'access_request'").groupby("sample_key").size().reindex(sm.index, fill_value=0)
    _check(rows, "metadata", "structure.access_count == observed access_request events",
           (obs_access == sm["structure.access_count"]).all(),
           f"{(obs_access != sm['structure.access_count']).sum()} mismatches")
    exp_len = sm["structure.base_event_count"] + sm["transformation_delta.event_count_delta"]
    _check(rows, "metadata", "n_events == base_event_count + event_count_delta",
           (exp_len == sm["n_events"]).all(), f"{(exp_len != sm['n_events']).sum()} mismatches")
    kind_vs_truth = ((sm["role_kind"] == "anomaly") == (sm["detector_truth"] == "anomaly")).all()
    _check(rows, "metadata", "role.kind == 'anomaly' ⇔ detector_truth == 'anomaly'", bool(kind_vs_truth), "")
    _check(rows, "metadata", "role is listed in applicable_scientific_roles",
           all(r in a.split("|") for r, a in zip(sm["role"], sm["applicable_scientific_roles"])), "")
    _check(rows, "metadata", "base traces are unique (no sample built from the same base twice)",
           sm["base.base_construction_key"].is_unique,
           f"{sm['base.base_construction_key'].nunique()} unique base keys")
    _check(rows, "metadata", "all generator gates passed",
           bool(sm["aggregate_gate_passed"].all() and sm["canonical_reload_valid"].all()
                and (sm["collision_classification"] == "none").all()), "aggregate_gate, canonical_reload, collision")
    const = [c for c in samples.columns if samples[c].nunique(dropna=False) == 1]
    _check(rows, "metadata", "constant metadata columns (carry no information)", True,
           f"{len(const)} constant: " + ", ".join(const), warn=True)

    out = pd.DataFrame(rows)
    out.to_csv(paths.tables / "validation_checks.csv", index=False, lineterminator="\n")
    return out
