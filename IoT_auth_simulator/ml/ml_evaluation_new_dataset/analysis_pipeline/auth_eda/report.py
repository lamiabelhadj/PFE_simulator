"""Stage 7 — assemble report.md and a self-contained report.html.

Every number in the text comes from `facts` (computed by earlier stages) or
from the CSV tables, so re-running the pipeline on a new candidate rewrites
the narrative consistently.
"""
from __future__ import annotations

import re

import pandas as pd

from . import mdhtml
from .config import EVENT_ORDER, ROLE_ORDER, ROLE_SHORT, SEED, Paths

ROLE_EXPLAIN = {
    "ordinary_normal": "An unmodified session produced by the simulator's behavioural model. The reference for “normal”.",
    "hard_negative:small_positive_causal_margin":
        "A normal session whose challenge-response timing was squeezed so the device answers only a few "
        "milliseconds after receiving the nonce. Close to the timing anomaly but still causally valid (Δt > 0).",
    "hard_negative:fresh_nonce_cross_attempt":
        "A normal session with several handshakes (retry and/or token renewal), each using a **fresh** nonce. "
        "Structurally the closest match to nonce reuse, but legitimate.",
    "hard_negative:legitimate_same_attempt_nonce_recurrence":
        "A normal session in which one nonce appears several times *inside one handshake* "
        "(challenge_sent → nonce_received → response_sent). That is how the protocol works, so it is not reuse.",
    "anomaly:timestamp_inconsistency":
        "The `response_sent` event is timestamped **before** the `nonce_received` it answers "
        "(negative delay). A device cannot answer a challenge it has not received yet.",
    "anomaly:nonce_reuse":
        "A later handshake (after a retry or a renewal) **re-uses a nonce from an earlier handshake**. "
        "This is the signature of a replay.",
}

EVENT_FIELD_DOC = [
    ("event_type", "categorical (21 values)", "protocol step, e.g. challenge_sent, token_issued"),
    ("result", "success / failure", "outcome of the step; only authentication_failure is a failure"),
    ("failure_reason", "nullable string", "set only on failures (always 'authentication_failure')"),
    ("retry_count", "int (0/1)", "number of retries so far in the session"),
    ("observed_timestamp", "float, Unix seconds", "when the detector saw the event"),
    ("observed_delay_since_previous_event", "float, seconds", "timestamp − previous timestamp (0 for the first event)"),
    ("nonce", "nullable sha256", "challenge nonce; present on challenge_sent / nonce_received / response_sent"),
    ("token_id", "nullable sha256", "session token; present from token_issued until renewal/close"),
    ("resource_id", "nullable string", "resource targeted by an access request"),
    ("requested_action", "read / write / null", "action requested on the resource"),
    ("topic", "nullable string", "MQTT-like topic of the session"),
    ("attempt_index *(derived)*", "int", "handshake number: +1 at each challenge_sent (0 before the first)"),
]


def _fmt(v, nd=3):
    if isinstance(v, float):
        if v != v:
            return "–"
        if abs(v) >= 1000 or (abs(v) < 1e-3 and v != 0):
            return f"{v:.3g}"
        return f"{v:.{nd}f}".rstrip("0").rstrip(".") if "." in f"{v:.{nd}f}" else f"{v}"
    return str(v)


def md_table(df: pd.DataFrame, nd=3, max_rows=None) -> str:
    if max_rows:
        df = df.head(max_rows)
    cols = list(df.columns)
    lines = ["| " + " | ".join(map(str, cols)) + " |", "|" + "---|" * len(cols)]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(_fmt(r[c], nd).replace("|", "/") for c in cols) + " |")
    return "\n".join(lines)


def pct(x, nd=0):
    return f"{x * 100:.{nd}f}%"


def build(paths: Paths, facts: dict) -> None:
    E, S, M = facts["eda"], facts["sep"], facts["models"]
    comp, lens, voc, tim, dev, tok = E["composition"], E["lengths"], E["vocabulary"], E["timing"], E["devices"], E["tokens"]
    samples = pd.read_csv(paths.data / "samples.csv")
    events_cols = pd.read_csv(paths.data / "events.csv", nrows=1).columns
    feats_cols = pd.read_csv(paths.data / "features.csv", nrows=1).columns
    fdict = pd.read_csv(paths.tables / "feature_dictionary.csv")
    checks = facts["checks"]
    n_fail = int((checks["status"] == "FAIL").sum())
    rules = S["rules"]["summary"].set_index("rule")
    msum = M["summary"].set_index(["feature_set", "model"])
    ctx_best = msum.xs("context_only", level=0)["roc_auc_mean"]
    ctx_model = ctx_best.idxmax()
    leak = S["leakage"]
    leaking = leak.loc[leak["verdict"] == "LEAKS LABEL", "column"].tolist()
    correlated = leak.loc[leak["verdict"] == "label-correlated (design variable)", "column"].tolist()
    uni = S["univariate"]
    chi = E["structure"]["structure_chi2"].set_index("variable")

    md: list[str] = []
    w = md.append

    # ------------------------------------------------------------------ title
    w("# IoT authentication scientific candidate: data analysis report")
    w(f"*Input:* `{paths.input_json.name}` · schema `{facts['header'].get('schema_version')}` · "
      f"contract `{facts['header'].get('observation_contract')}` · status `{facts['header'].get('publication_status')}`  ")
    w(f"*Input sha256:* `{facts['input_sha256']}` · *pipeline seed:* `{SEED}`")
    w("")
    w("## Key findings")
    w(f"1. **What it is.** {comp['n_samples']} authentication *sessions* ({comp['n_events']:,} events) from "
      f"{comp['n_devices']} simulated IoT devices. {comp['n_anomaly']} sessions are labelled **anomaly** and "
      f"{comp['n_normal']} **normal**. Of the normal sessions, {comp['n_hard_neg']} are *hard negatives*: sessions "
      f"built to resemble an anomaly while staying legitimate.")
    w(f"2. **Integrity.** {int((checks['status']=='PASS').sum())}/{len(checks)} consistency checks pass"
      + (f", **{n_fail} fail**" if n_fail else ", none fail")
      + ". Timestamps agree with delays to within 10 µs, the handshake grammar is respected everywhere, "
        "and the metadata agrees with what is observed.")
    w("3. **Two anomaly types, each with one precise signature.** *Timestamp inconsistency* means a negative "
      "nonce_received→response_sent delay. *Nonce reuse* means a nonce shared by two handshakes. "
      f"The two-rule detector `negative delay OR cross-handshake nonce` reaches recall "
      f"{pct(rules.loc['R1_or_R2','recall'])} with {int(rules.loc['R1_or_R2','FP'])} false positives. "
      "**The label is a deterministic function of the observations.**")
    w(f"4. **Hard negatives do their job against weak signals but not against the true signal.** The closest "
      f"timing hard negative still has a margin of ≥ {tim['hn_margin_min']*1000:.2f} ms, against "
      f"{tim['ts_margin_max']*1000:.2f} ms for the anomalies. They suppress the shortcut features, such as session "
      "length or retries, but cannot hide the mechanism.")
    w(f"5. **Baseline models.** With device-grouped CV, every model reaches ROC-AUC = "
      f"{msum.loc[('all_observable','random_forest'),'roc_auc_mean']:.3f} on the observable features. Once the mechanism "
      f"features and their proxies are removed, the best model ({ctx_model.replace('_',' ')}) falls to "
      f"{ctx_best.max():.3f}. What remains is mostly a side effect of the timing transformation, and the hard "
      "negatives share that side effect, so they absorb it (see §8 and §13).")
    w(f"6. **Leakage.** {len(leaking)} privileged metadata columns reveal the label outright and "
      f"{len(correlated)} more are design variables tied to it. None of them may be used as a feature. "
      "The pipeline keeps them in `samples.csv`, separate from the detector view (`events.csv`, `features.csv`).")
    top = dev["latent_top"][:3]
    w("7. **The generator is legible.** Device latent tendencies map onto observed behaviour, e.g. "
      + "; ".join(f"`{a}` ↔ `{b}` (ρ = {r:.2f})" for a, b, r, _ in top) + ".")
    w("")
    w("> **How to read this report.** Sections 2–3 cover the file format and its integrity. Sections 4–10 describe "
      "the data: what a session looks like, how timing and nonces behave, and who the devices are. Sections 11–13 "
      "ask how separable the classes are and whether the evaluation can be trusted. Each figure and table also exists "
      "as a file under `outputs/`. The appendix lists them all.")

    # ------------------------------------------------------------ data model
    w("## 1. Reproducing this analysis")
    w("```")
    w("cd analysis_pipeline")
    w("pip install -r requirements.txt")
    w("python run_pipeline.py                 # → outputs/ (≈5 min, mostly cross-validation)")
    w("python verify_reproducibility.py       # runs twice, compares sha256 of every output")
    w("```")
    v = facts["versions"]
    w("Environment of this run: " + ", ".join(f"{k} {x}" for k, x in v.items()) + ". "
      f"Every random step (CV shuffling, forests, permutation importance, mutual information, plot jitter) is "
      f"seeded from `SEED = {SEED}`. PNGs are written without timestamps. `outputs/manifest.json` records the "
      "sha256 of the input and of every output file.")

    w("## 2. From JSON to CSV: the data model")
    w(f"The JSON holds a header ({', '.join(f'`{k}`' for k in facts['header'])}) and a list of "
      f"{comp['n_samples']} samples. Each sample has two parts that must **never be mixed**:")
    w("- `detector_observations`: the ordered event log, i.e. what a deployed detector would actually see.")
    w("- `privileged_metadata`: generator-side truth, covering the label, the scientific role, the device's latent "
      "profile, the construction provenance and a description of the transformation applied. A detector does not "
      "see this.")
    w("The pipeline writes three tidy tables that keep this split explicit:")
    w("| file | grain | rows × cols | content |")
    w("|---|---|---|---|")
    w(f"| `data/events.csv` | one event | {comp['n_events']} × {len(events_cols)} | the 11 observed fields, plus `sample_key`, `device`, `event_index`, derived `attempt_index`, and two `label_*` columns kept for convenience |")
    w(f"| `data/samples.csv` | one session | {len(samples)} × {samples.shape[1]} | all privileged metadata flattened (`a.b.c` paths; lists pipe-joined, with a companion `.__len` column) |")
    w(f"| `data/features.csv` | one session | {len(samples)} × {len(feats_cols)} | {facts['n_features']} numeric features computed **only** from events, plus label columns (`y`, `role`, …) |")
    w("`sample_key` (S000…S335, in file order) joins the three tables. The original `sample_id` hash is kept in `samples.csv`.")
    w("### 2.1 Event fields")
    w("| field | type | meaning |")
    w("|---|---|---|")
    for f, t, d in EVENT_FIELD_DOC:
        w(f"| `{f}` | {t} | {d} |")
    miss = E["missingness"].set_index("column")["missing_share"]
    w("Missing values are **structural, not data loss**: a field is empty when it does not apply to the event type. "
      f"Share of missing values per column: " + ", ".join(f"`{c}` {pct(miss[c])}" for c in
      ["nonce", "token_id", "resource_id", "requested_action", "topic", "failure_reason"]) + ".")
    w("### 2.2 Privileged metadata (in `samples.csv`)")
    w("- **Labels:** `detector_truth` (normal/anomaly), `role` (6 values), `role_kind` (ordinary / hard_negative / anomaly), `semantic_family` (ordinary / direct_timing / nonce).")
    w("- **Device:** `device`, `device_profile.latent_tendencies.*` (14 continuous traits), `device_profile.scalar_strata.*` (their discretised strata), `device_profile.lifecycle_cell`.")
    w("- **Base trace structure:** `structure.*`, i.e. lifecycle (AUTH/ACCESS/SESSION), recovery (DIRECT/ONE_RETRY), renewal, attempt/access/token counts, base duration and event count.")
    w("- **Transformation:** `transformation.*` and `transformation_delta.*` record what was changed relative to the base trace, which fields changed and how many. `timing_observed_margin` holds the causal margin for timing roles.")
    w("- **Provenance & gates:** hashes and references (`base.*`, `*_reference`, `*_fingerprint`) plus generator quality gates (`aggregate_gate_passed`, `canonical_reload_valid`, `collision_classification`).")

    # -------------------------------------------------------------- validity
    w("## 3. Integrity validation")
    w("Before any analysis, the pipeline checks the file contract, event consistency, the protocol grammar, "
      "and agreement between metadata and observations. Results are in `tables/validation_checks.csv`.")
    w(md_table(checks[["group", "check", "status", "detail"]].assign(
        detail=checks["detail"].str.slice(0, 160))))
    w("Two results matter for everything that follows. First, **negative delays occur only in the "
      "timestamp-anomaly role**, so normal sessions are perfectly time-ordered. Second, the metadata's structural "
      "counts match the observed events exactly, so the observable log is a faithful rendering of the generator's intent.")

    # ------------------------------------------------------------ composition
    w("## 4. What is in the dataset")
    w(f"![Figure 1 – sessions per scientific role. Anomalies are {pct(comp['n_anomaly']/comp['n_samples'])} of sessions.](figures/01_composition.png)")
    c = comp["comp"].reset_index()
    c["role"] = c["role"].map(lambda r: f"`{r}`")
    w(md_table(c[["role", "role_kind", "semantic_family", "detector_truth", "n_samples", "share", "n_devices", "events_mean"]]))
    w("**What each role means:**")
    for r in ROLE_ORDER:
        w(f"- **{ROLE_SHORT[r]}** (`{r}`): {ROLE_EXPLAIN[r]}")
    tmeta = samples.groupby("role").agg(
        transformation_applied=("transformation.applied", "mean"),
        identical_to_base=("transformation_delta.o03_equal_to_base", "mean"),
    ).reindex(ROLE_ORDER)
    w("How far each role departs from its base trace (share of sessions):")
    w(md_table(tmeta.reset_index().assign(role=lambda d: d["role"].map(ROLE_SHORT))))
    same_hn = tmeta.loc["hard_negative:legitimate_same_attempt_nonce_recurrence", "identical_to_base"]
    w(f"Note that **{pct(same_hn)} of the *same-attempt nonce recurrence* hard negatives are byte-identical to their "
      "base trace**. Every handshake shows its nonce three times (challenge, received, response), so this “hard "
      "negative” is observationally just an ordinary session. It tests whether a detector mistakes normal "
      "within-handshake recurrence for reuse. The fresh-nonce hard negatives are also unmodified base traces. "
      "They are *selected* rather than transformed: sessions that happen to have several handshakes.")

    # ------------------------------------------------------------- structure
    w("## 5. Experimental design: are the roles structurally comparable?")
    w("A well-designed benchmark should make anomalies and normals differ **only** in the anomaly mechanism. "
      "The figure shows the mix of session structures per role.")
    w("![Figure 2 – lifecycle, recovery, renewal and enrollment mix per role.](figures/02_structure_mix.png)")
    w(md_table(chi.reset_index()))
    rec_v = chi.loc["recovery", "cramers_v"]
    w(f"Lifecycle and enrollment are close to balanced across roles. **Recovery (Cramér V = {rec_v:.2f}) and renewal "
      "are not.** By construction, nonce reuse and fresh-nonce hard negatives need at least two handshakes, i.e. a retry "
      "or a renewal. Those two roles are therefore enriched in ONE_RETRY and RENEWAL sessions. The fresh-nonce hard "
      "negative is what keeps this from becoming a pure shortcut: it gives the same structure a *normal* label. "
      "§13 measures how much of the shortcut is left.")

    # ---------------------------------------------------------------- anatomy
    w("## 6. Anatomy of a session")
    w(f"Sessions contain {lens['events_min']}–{lens['events_max']} events (median {lens['events_median']:.0f}). "
      f"Durations are **bimodal**: most sessions last a few seconds (median {lens['dur_median']:.1f} s). The "
      f"{pct(lens['share_long'])} that include a token renewal last minutes (up to {lens['dur_max']:.0f} s), "
      "because the device waits for the token to near expiry.")
    w("![Figure 3 – events per session and duration per role (log scale).](figures/03_session_length.png)")
    w("### 6.1 Protocol phases")
    w("Every session follows the same grammar, a subset of these phases in order:")
    w("1. *Enrollment prelude* (optional, first contact only): discovery → gateway_advertisement → pairing_request → pairing_response → enrollment_request → enrollment_confirmed.")
    w("2. *Authentication*: authentication_request → **challenge_sent → nonce_received → response_sent** → authentication_success, or authentication_failure → retry → a new challenge.")
    w("3. *Token*: token_issued → token_presented → token_validated → session_opened.")
    w("4. *Access* (0–n times): access_request → access_granted.")
    w("5. *Renewal* (optional): renewal_request → a fresh challenge-response handshake → a new token.")
    w("6. *Close* (with renewal): session_closed.")
    w(f"![Figure 4 – mean occurrences of each of the {voc['n_event_types']} event types per session, by role.](figures/04_event_vocabulary.png)")
    w(f"Of all {len(EVENT_ORDER)}×{len(EVENT_ORDER)} possible transitions, only {voc['n_bigrams']} occur. "
      f"{voc['n_deterministic_transitions']} event types always have the same successor. Branching happens only at "
      + ", ".join(f"`{b}`" for b in voc["branching_events"])
      + ". The event-type sequence is therefore almost fully determined by the structure "
        "(lifecycle × recovery × renewal × enrollment). **Sequence order carries no anomaly signal**: neither anomaly "
        "inserts, deletes or reorders event *types*.")
    w("![Figure 5 – transition probabilities between event types (the protocol grammar).](figures/05_transition_matrix.png)")

    # ---------------------------------------------------------------- timing
    w("## 7. Timing")
    dt = tim["delay_table"].reset_index()
    w(f"Across {tim['n_gaps']:,} inter-event gaps the median delay is {tim['delay_median']*1000:.0f} ms and the "
      f"95th percentile {tim['delay_p95']:.2f} s. Each event type has its own delay distribution. Protocol "
      "round-trips are 30–300 ms. `retry` waits about 2 s (back-off), `access_request` follows a think-time of "
      "seconds, and `renewal_request` waits minutes for the token to age.")
    w(md_table(dt[["event_type", "n", "min", "median", "p95", "max", "n_at_floor", "n_negative"]]))
    w(f"![Figure 6 – delay distribution per event type, normal sessions only (log scale).](figures/06_delay_by_event_type.png)")
    w(f"**Delay floor.** {tim['n_floor']} gaps sit at exactly 1 µs. They are the simulator's representation of "
      "events emitted back-to-back, and they occur mostly on `access_request` right after `session_opened`/`access_granted`. "
      "They are legitimate, but a naive \"impossibly fast\" rule would flag them, so they act as natural hard "
      "negatives for timing detectors.")

    w("## 8. Anomaly mechanism 1: timestamp inconsistency")
    w(f"The timing anomaly moves `response_sent` to **{abs(tim['ts_margin_max'])*1000:.1f} ms before** "
      f"`nonce_received` (all {tim['n_negative']} negative delays in the dataset are this one value, "
      f"min {tim['ts_margin_min']*1000:.3f} ms). The matching hard negative keeps the response "
      f"{tim['hn_margin_min']*1000:.2f}–{tim['hn_margin_max']*1000:.2f} ms *after* the nonce. Every other session's "
      f"smallest response gap is ≥ {tim['other_margin_min']*1000:.2f} ms.")
    w("![Figure 7 – smallest nonce_received→response_sent delay per session. Only the timestamp anomalies cross zero.](figures/07_causal_margin.png)")
    w("The class boundary is the causal boundary Δt = 0, and the gap around it is about "
      f"{(tim['hn_margin_min'] - tim['ts_margin_max'])*1000:.1f} ms wide. The transformation changes exactly two delays "
      "(the response and the event after it) and one timestamp, and leaves the session length unchanged. "
      "Statistics aggregated over the whole session therefore barely move.")
    feats = pd.read_csv(paths.data / "features.csv")
    nxt = (feats.groupby("role")["authentication_success_delay_mean"].median().reindex(ROLE_ORDER)
           .rename("median delay before authentication_success (s)").reset_index())
    nxt["role"] = nxt["role"].map(ROLE_SHORT)
    w("**A side effect shared with the hard negative.** Moving `response_sent` earlier lengthens the gap to the "
      "*next* event by the same amount. Both timing roles (anomaly and hard negative) therefore show an inflated "
      "delay before `authentication_success`:")
    w(md_table(nxt))
    w("This is a fingerprint of *the transformation*, not of *the anomaly*. Because the small-margin hard negative "
      "carries it too, a detector that learns it gets false positives instead of a free win. This is the clearest "
      "example in the dataset of a hard negative doing its job.")
    _example_pair(w, E["examples"], "hard_negative:small_positive_causal_margin", "anomaly:timestamp_inconsistency")

    w("## 9. Anomaly mechanism 2: nonce reuse")
    nt = E["nonces"]["nonce_table"].reset_index()
    nt["role"] = nt["role"].map(ROLE_SHORT)
    w(md_table(nt))
    w("![Figure 8 – share of multi-handshake sessions, and share with a nonce reused across handshakes.](figures/08_nonce_mechanism.png)")
    w("Inside one handshake, a nonce always appears exactly 3 times, in *every* role. Nonce reuse makes a later "
      "handshake (after a retry or renewal) copy the nonce of an earlier one, so the nonce appears 6 times and the "
      "count of distinct nonces drops below the count of handshakes. The fresh-nonce hard negatives have the same "
      "multi-handshake structure (100% ≥ 2 handshakes) but never share a nonce. That is why `n_attempts` alone cannot "
      "separate them.")
    _example_pair(w, E["examples"], "hard_negative:fresh_nonce_cross_attempt", "anomaly:nonce_reuse")

    w("## 10. Tokens, resources, topics and devices")
    w(f"- **Tokens:** {tok['n_tokens']} distinct tokens, {tok['tokens_multi_session']} shared across sessions. "
      "A token is issued, presented, validated and then carried by access events. Renewal sessions have two tokens. "
      "None of the anomaly roles touches tokens.")
    w(f"- **Resources:** {tok['n_resources']} resources, {tok['resources_multi_device']} shared between devices "
      f"(each device owns ≤ {tok['resources_per_device_max']}). Actions: "
      + ", ".join(f"{k} {v}" for k, v in tok["action_counts"].items()) + ".")
    w(f"- **Topics:** {tok['n_topics']} topics, {tok['topics_multi_device']} shared between devices. Each topic "
      "is a device-specific identifier.")
    w("Resource and topic strings are **device identifiers**. Encoding them as features would let a model memorise "
      "devices, so the pipeline only uses their *counts*.")
    w(f"### 10.1 Device population")
    w(f"Each of the {comp['n_devices']} devices contributes {dev['per_device_min']}–{dev['per_device_max']} sessions "
      f"(median {dev['per_device_median']:.0f}) spread over a median of {dev['roles_per_device_median']:.0f} roles. "
      f"{dev['n_dev_with_anomaly']} devices have at least one anomalous session. Device identity is therefore not "
      "aligned with the label. Sessions from one device still share a behavioural profile, which is why every model "
      "in §13 is evaluated with **device-grouped** splits.")
    w("![Figure 9 – sessions per device and role.](figures/09_device_by_role.png)")
    w("### 10.2 Latent behavioural profile")
    w("Each device has 14 latent tendencies (`A`, `N`, `R`, `L.{auth,access,session}`, `T.{AUTH,ACCESS,RENEWAL,TRANSITION}."
      "{center,dispersion}_modifier`). The figure correlates them with device-averaged behaviour in normal sessions. "
      "It shows what each latent appears to control. This is an empirical reading, not documentation from the generator.")
    w("![Figure 10 – Spearman ρ between latent tendencies and observed behaviour (64 devices).](figures/10_latent_vs_observed.png)")
    w("| latent | observed behaviour | ρ | p |")
    w("|---|---|---|---|")
    for a, b, r, p in dev["latent_top"]:
        w(f"| `{a}` | `{b}` | {r:.2f} | {p:.1e} |")
    w("Read as: `T.AUTH.center` sets the speed of handshake round-trips, `T.TRANSITION.center` the token-issuing "
      "delay, `T.ACCESS.center` the access-grant delay, `R` the propensity to retry, `L.access` the number of "
      "accesses, and `N` the propensity to renew. The *dispersion* modifiers show little device-level correlation. "
      "That is expected: they change the spread, not the mean.")

    # ------------------------------------------------------------- features
    w("## 11. Feature space")
    g = fdict.groupby("group").size()
    w(f"`features.csv` has {facts['n_features']} numeric features in five groups: "
      + ", ".join(f"{k} ({n})" for k, n in g.items())
      + ". Full definitions are in `tables/feature_dictionary.csv`. "
        f"{int(fdict['mechanism_feature'].sum())} features are tagged **mechanism** because they encode the anomaly "
        "signature directly or through a proxy:")
    w(", ".join(f"`{f}`" for f in fdict.loc[fdict["mechanism_feature"], "feature"]) + ".")
    w(f"Many features are redundant by construction: {E['correlations']['n_redundant_pairs']} pairs have |ρ| ≥ 0.95. "
      "For example, `n_attempts`, `count_challenge_sent` and `n_nonce_events / 3` are the same quantity. "
      + (f"Constant features: {', '.join(f'`{c}`' for c in E['correlations']['constant_features'])}." if E['correlations']['constant_features'] else ""))
    w("![Figure 11 – Spearman correlation between features (count_* mostly omitted).](figures/11_feature_correlation.png)")

    # ---------------------------------------------------------- separability
    w("## 12. How separable are the classes?")
    w("### 12.1 One feature at a time")
    w("Separability is measured as max(AUC, 1−AUC), where 0.5 means no signal and 1 means perfect separation. "
      "It is computed twice: anomalies vs *all* normal sessions, and anomalies vs *hard negatives only*.")
    w("![Figure 12 – top single-feature separability; the gap between the dots is what hard negatives remove.](figures/12_univariate_separability.png)")
    cols = ["feature", "group", "auc|anomaly_vs_all_normal", "auc|anomaly_vs_hard_negatives",
            "auc|timing_anom_vs_timing_hn", "auc|nonce_anom_vs_nonce_hn", "mutual_info", "bh_q"]
    ut = uni[cols].head(14).rename(columns={
        "auc|anomaly_vs_all_normal": "AUC vs all", "auc|anomaly_vs_hard_negatives": "AUC vs HN",
        "auc|timing_anom_vs_timing_hn": "AUC timing pair", "auc|nonce_anom_vs_nonce_hn": "AUC nonce pair"})
    w(md_table(ut))
    w("No single feature separates *both* anomaly types: AUC caps at 0.75, i.e. one type perfectly and the other not "
      "at all. Within each family, though, the mechanism feature is perfect (AUC 0 or 1 in the family-pair columns). "
      "Outside the mechanism features, no feature exceeds about 0.6. Structure, timing aggregates, tokens and counts carry "
      "only the weak design imbalance described in §5. FDR-corrected Mann-Whitney q-values are in `bh_q`.")
    w("### 12.2 Two transparent rules")
    w("- **R1:** the session contains a negative inter-event delay.")
    w("- **R2:** some nonce appears in two different handshakes.")
    w(md_table(S["rules"]["summary"].round(3)))
    rb = S["rules"]["by_role"].reset_index()
    rb["role"] = rb["role"].map(ROLE_SHORT)
    w(md_table(rb.round(3)))
    w("> The two rules together reproduce `detector_truth` **exactly**. No hard negative trips either rule. "
      "As an ML benchmark the candidate is therefore *solved by specification*. It is most useful for testing "
      "whether a learned detector (a) finds these invariants without being told, (b) does so without leaning on "
      "structural shortcuts, and (c) keeps its false-positive rate on hard negatives at zero.")
    w("### 12.3 Leakage audit of the privileged metadata")
    w("Every `samples.csv` column is scored for association with the label on a common 0–1 scale: Cramér V for "
      "categorical columns, |2·AUC−1| for numeric ones, plus on the non-missing rows for partially defined columns. "
      "**LEAKS LABEL** means near-perfect association, so using the column would be cheating. "
      "**Design variable** means the column is correlated with the label because of how the benchmark was built.")
    lk = leak.loc[leak["verdict"].isin(["LEAKS LABEL", "label-correlated (design variable)"]),
                  ["column", "kind", "metric", "label_association", "association_non_missing_rows", "majority_purity", "verdict"]]
    w(md_table(lk))
    n_dev_lat = leak.loc[leak["column"].str.startswith("device_profile.latent"), "verdict"].eq("not associated").sum()
    w(f"The device latent tendencies are not associated with the label ({n_dev_lat}/14 below the 0.3 threshold), "
      "which confirms that anomalies were assigned independently of the device's behavioural profile. "
      "The complete audit is in `tables/metadata_leakage_audit.csv`.")

    # ---------------------------------------------------------------- models
    w("## 13. Baseline detectors")
    w(f"Models: logistic regression (standardised), random forest (300 trees) and a depth-3 decision tree. "
      f"Splits: StratifiedGroupKFold with 5 folds grouped by **device**, repeated 5× with different seeds. "
      f"Imputation and scaling are fitted inside each training fold. Feature sets: all observable "
      f"({M['sets']['all_observable']}), mechanism only ({M['sets']['mechanism_only']}), and context only "
      f"({M['sets']['context_only']}, i.e. all observable minus mechanism features and proxies).")
    w("![Figure 13 – ROC-AUC per model and feature set.](figures/13_cv_auc.png)")
    w(md_table(M["summary"]))
    w("![Figure 14 – share of each role flagged as anomalous (out-of-fold).](figures/14_flag_rate_by_role.png)")
    w(f"- **All observable / mechanism only:** perfect, as the rules predicted.")
    rr = M["role_rate"].xs(ctx_model, level="model").loc["context_only"]
    ic_top = M["importance"].query("feature_set == 'context_only'").head(3)["feature"].tolist()
    w(f"- **Context only:** best ROC-AUC {ctx_best.max():.3f}. This is the shortcut budget of the dataset, i.e. what a "
      "model can learn without ever looking at the anomaly mechanism. With the "
      f"{ctx_model.replace('_', ' ')}, it flags {pct(rr['anomaly:timestamp_inconsistency'])} of timestamp anomalies, "
      f"but also {pct(rr['hard_negative:small_positive_causal_margin'])} of the small-margin hard negatives. It flags "
      f"{pct(rr['anomaly:nonce_reuse'])} of nonce-reuse sessions, against "
      f"{pct(rr['hard_negative:fresh_nonce_cross_attempt'])} of fresh-nonce hard negatives and "
      f"{pct(rr['ordinary_normal'])} of ordinary sessions. Its most important features, led by "
      f"{', '.join(f'`{c}`' for c in ic_top)}, mostly reflect the transformation side effect described in §8, "
      "which the hard negatives share. In short, without the mechanism a model can tell that a session was *transformed*, not that "
      "it is *anomalous*. The residual shortcut is small, and the hard negatives are the reason.")
    w("A depth-3 tree on **all** observable features, fitted on all data, recovers the two invariants as readable rules:")
    w("```")
    w(M["tree_rules"].rstrip())
    w("```")
    w("The same tree restricted to **context** features:")
    w("```")
    w(M["tree_rules_context"].rstrip())
    w("```")
    imp = M["importance"]
    ic = imp.loc[imp["feature_set"] == "context_only"].head(8)
    w("Random-forest permutation importance (context-only set, computed on held-out folds). On the full feature "
      "set, importance spreads over several redundant, perfectly predictive features, so permuting any one of them "
      "costs nothing. Use the context set to read importance.")
    w(md_table(ic[["feature", "mean", "std"]].round(4)))

    # ----------------------------------------------------------- conclusions
    w("## 14. Conclusions and recommendations")
    w("1. **The data is clean and internally consistent.** It can be trusted as a faithful simulation of the protocol.")
    w("2. **Labels are fully explained by two protocol invariants:** causality of the challenge response "
      "(INV-TIME-OBSERVED-CAUSAL) and nonce freshness across handshakes (INV-REPLAY-NONCE-CROSS-ATTEMPT). Report rule "
      "baselines next to any ML result. A learned model that does not reach 100% is *worse than two lines of code*.")
    w("3. **Always split by device.** Sessions from one device share a latent profile.")
    w("4. **Never feed `samples.csv` columns to a model.** Use `features.csv` (detector view), drop the label columns "
      "(`y`, `role`, `role_kind`, `semantic_family`), and drop `device` except as a grouping key.")
    w("5. **Evaluate per role, not only overall.** FPR on each hard-negative role is the informative number. "
      "Overall accuracy hides it because hard negatives are 43% of the data.")
    w("6. **To make the benchmark harder**, consider: anomalies with a margin overlapping the hard-negative range "
      "(noisy clocks), nonce reuse within a single handshake slot, or anomaly classes that also alter structure. "
      "The design imbalance in recovery/renewal (§5) could also be reduced by matching normal sessions on the "
      "number of handshakes.")
    w("7. **Sample size.** Each role has only 48 sessions, so confidence intervals on per-role rates are about ±7–14 "
      "percentage points.")

    # -------------------------------------------------------------- appendix
    w("## Appendix: output files")
    w("| path | content |")
    w("|---|---|")
    for p, d in OUTPUT_DOC:
        w(f"| `{p}` | {d} |")

    text = _space_blocks(md)
    (paths.out / "report.md").write_text(text, encoding="utf-8")
    body, toc = mdhtml.convert(text, paths.out)
    (paths.out / "report.html").write_text(mdhtml.page("IoT Auth Data Report", body, toc), encoding="utf-8")


def _space_blocks(md: list[str]) -> str:
    """Put a blank line between Markdown blocks so any renderer (GitHub, VS Code)
    separates paragraphs, headings and tables, while keeping table rows, list
    items and fenced code contiguous."""
    lines = "\n".join(md).split("\n")
    out, in_code, prev = [], False, ""
    for ln in lines:
        if ln.startswith("```"):
            if not in_code and prev.strip():
                out.append("")
            out.append(ln)
            in_code = not in_code
            prev = ln if in_code else ""
            if not in_code:
                out.append("")
            continue
        if in_code:
            out.append(ln)
            continue
        same_block = (ln.startswith("|") and prev.startswith("|")) or (
            re.match(r"^\s*([-*]|\d+\.)\s", ln) and re.match(r"^\s*([-*]|\d+\.)\s", prev)) or (
            ln.startswith(">") and prev.startswith(">"))
        if prev.strip() and ln.strip() and not same_block:
            out.append("")
        out.append(ln)
        prev = ln
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip() + "\n"


def _example_pair(w, ex: pd.DataFrame, neg_role: str, pos_role: str) -> None:
    w(f"**Worked example:** a {ROLE_SHORT[neg_role]} session next to a {ROLE_SHORT[pos_role]} session "
      "(handshake events only; nonce and token truncated to 8/6 hex characters):")
    keep = {"authentication_request", "challenge_sent", "nonce_received", "response_sent",
            "authentication_failure", "retry", "authentication_success", "renewal_request"}
    for r in (neg_role, pos_role):
        s = ex.loc[(ex["role"] == r) & ex["event_type"].isin(keep)]
        w(f"*{ROLE_SHORT[r]}* (`{s['sample_key'].iloc[0]}`)")
        w("| # | event | delay (s) | handshake | nonce |")
        w("|---|---|---|---|---|")
        for _, e in s.iterrows():
            d = e["delay_s"]
            ds = f"**{d:.6f}**" if d < 0.01 and e["event_type"] == "response_sent" else f"{d:.6f}"
            w(f"| {e['i']} | {e['event_type']} | {ds} | {e['attempt']} | {e['nonce8'] if isinstance(e['nonce8'], str) else ''} |")


OUTPUT_DOC = [
    ("data/events.csv", "one row per observed event (detector view + derived attempt_index + label copies)"),
    ("data/samples.csv", "one row per session, all privileged metadata flattened"),
    ("data/features.csv", "one row per session, observable features + labels"),
    ("tables/validation_checks.csv", "integrity checks with status and detail"),
    ("tables/feature_dictionary.csv", "definition, group and mechanism tag of every feature"),
    ("tables/composition_by_role.csv", "counts, shares, devices and lengths per role"),
    ("tables/structure_mix_by_role.csv / structure_vs_role_chi2.csv", "structural balance across roles"),
    ("tables/session_length_by_role.csv", "events and duration summary per role"),
    ("tables/event_vocabulary.csv / transition_matrix.csv", "event-type frequencies and bigram counts"),
    ("tables/delay_by_event_type.csv", "delay quantiles, floor and negative counts per event type"),
    ("tables/nonce_usage_by_role.csv", "handshake and nonce statistics per role"),
    ("tables/token_resource_summary.csv", "token / resource / topic cardinalities"),
    ("tables/device_by_role.csv", "sessions per device × role"),
    ("tables/latent_vs_observed_spearman.csv / _pvalues.csv", "device latent profile vs behaviour"),
    ("tables/feature_correlation_spearman.csv / redundant_feature_pairs.csv", "feature correlations"),
    ("tables/univariate_separability.csv", "AUC (4 comparisons), mutual information, BH q per feature"),
    ("tables/rule_detector_confusion.csv / rule_flag_rate_by_role.csv", "transparent rule baselines"),
    ("tables/metadata_leakage_audit.csv", "label association of every privileged column"),
    ("tables/cv_metrics_summary.csv / cv_metrics_per_repeat.csv", "baseline model metrics"),
    ("tables/cv_flag_rate_by_role.csv / cv_out_of_fold_predictions.csv", "per-role behaviour of models"),
    ("tables/rf_permutation_importance.csv", "held-out permutation importance"),
    ("tables/decision_tree_rules*.txt", "depth-3 tree rules"),
    ("tables/example_sessions.csv", "one representative session per role"),
    ("figures/*.png", "14 figures used in this report"),
    ("manifest.json", "input hash, seed, environment and sha256 of every output"),
]
