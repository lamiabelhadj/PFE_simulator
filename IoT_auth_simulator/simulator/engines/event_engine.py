"""
simulator/engines/event_engine.py
───────────────────────────────────
Layer 2 of 3 — Event Engine

Executes a ScenarioSpec into a correlated (List[AuthEvent], SessionContext) pair.

SessionContext
──────────────
Holds all device-level, network-level, MQTT-level, re-auth, and step-latency
attributes that were present in the Phase 0 feature set but cannot be derived
from AuthEvent objects alone.  It is generated alongside the event sequence
and merged into the feature table by output_views.to_feature_df().

Three session properties guaranteed
─────────────────────────────────────
  Temporal     — timestamps always increasing; delay_since_previous stored on every event
  State        — previous_state / new_state taken directly from StateMachine
  Consistency  — session_id, token_id, nonce propagated across all relevant events
"""

import hashlib
import math
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from simulator.config.settings import cfg
from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.state_machine import StateMachine, TransitionError
from simulator.engines.scenario_engine import ScenarioSpec
from simulator.engines.temporal_engine import TemporalEngine, TemporalConfig


# ── Severity map ──────────────────────────────────────────────────────────────
SEVERITY_MAP: Dict[str, str] = {
    "replay_token":             "medium",
    "nonce_reuse":              "medium",
    "timestamp_inconsistency":  "medium",
    "access_without_auth":      "high",
    "abnormal_failure_rate":    "high",
    "impersonation":            "high",
    "identity_token_mismatch":  "high",
    "abnormal_renewal":         "medium",
    "duplicate_sequence":       "medium",
    "connect_flood":            "high",
    "delayed_connect":          "high",
    "normal":                   "none",
}

# ── Attacker-class map (non_invasive | invasive | both) ───────────────────────
ATTACKER_CLASS_MAP: Dict[str, str] = {
    "replay_token":             "non_invasive",
    "nonce_reuse":              "non_invasive",
    "timestamp_inconsistency":  "non_invasive",
    "access_without_auth":      "non_invasive",
    "impersonation":            "non_invasive",
    "identity_token_mismatch":  "non_invasive",
    "duplicate_sequence":       "non_invasive",
    "abnormal_failure_rate":    "both",
    "connect_flood":            "both",
    "delayed_connect":          "both",
    "abnormal_renewal":         "invasive",
    "normal":                   "none",
}

# ── Delay profiles (mean, std) in seconds ─────────────────────────────────────
DELAY_PROFILE_NORMAL: Dict[EventType, Tuple[float, float]] = {
    EventType.DISCOVERY:              (0.0,  0.0),
    EventType.GATEWAY_ADVERTISEMENT:  (0.12, 0.04),
    EventType.PAIRING_REQUEST:        (0.10, 0.03),
    EventType.PAIRING_RESPONSE:       (0.18, 0.06),   # ECDH exchange cost
    EventType.ENROLLMENT_REQUEST:     (0.15, 0.05),
    EventType.ENROLLMENT_CONFIRMED:   (0.20, 0.07),
    EventType.REGISTRATION_REQUEST:   (0.0,  0.0),
    EventType.REGISTRATION_CONFIRMED: (0.08, 0.02),
    EventType.AUTHENTICATION_REQUEST: (0.5,  0.3),
    EventType.CHALLENGE_SENT:         (0.07, 0.02),
    EventType.NONCE_RECEIVED:         (0.15, 0.05),
    EventType.RESPONSE_SENT:          (0.25, 0.08),
    EventType.AUTHENTICATION_SUCCESS: (0.06, 0.02),
    EventType.AUTHENTICATION_FAILURE: (0.06, 0.02),
    EventType.TOKEN_ISSUED:           (0.08, 0.02),
    EventType.TOKEN_PRESENTED:        (0.12, 0.04),
    EventType.TOKEN_VALIDATED:        (0.06, 0.02),
    EventType.SESSION_OPENED:         (0.05, 0.01),
    EventType.ACCESS_REQUEST:         (2.0,  1.5),
    EventType.ACCESS_GRANTED:         (0.05, 0.01),
    EventType.ACCESS_DENIED:          (0.05, 0.01),
    EventType.SESSION_CLOSED:         (30.0, 20.0),
    EventType.RENEWAL_REQUEST:        (240.0, 30.0),
    EventType.TOKEN_EXPIRED:          (300.0, 10.0),
    EventType.RETRY:                  (1.0,  0.5),
    EventType.TIMEOUT:                (30.0, 5.0),
    EventType.DISCONNECT:             (5.0,  2.0),
}

DELAY_PROFILE_ATTACK: Dict[EventType, Tuple[float, float]] = {
    EventType.DISCOVERY:              (0.0,  0.0),
    EventType.GATEWAY_ADVERTISEMENT:  (0.05, 0.02),
    EventType.PAIRING_REQUEST:        (0.04, 0.01),
    EventType.PAIRING_RESPONSE:       (0.06, 0.02),
    EventType.ENROLLMENT_REQUEST:     (0.05, 0.02),
    EventType.ENROLLMENT_CONFIRMED:   (0.06, 0.02),
    EventType.REGISTRATION_REQUEST:   (0.0,  0.0),
    EventType.REGISTRATION_CONFIRMED: (0.04, 0.01),
    EventType.AUTHENTICATION_REQUEST: (0.05, 0.02),
    EventType.CHALLENGE_SENT:         (0.03, 0.01),
    EventType.NONCE_RECEIVED:         (0.02, 0.005),
    EventType.RESPONSE_SENT:          (0.03, 0.01),
    EventType.AUTHENTICATION_SUCCESS: (0.03, 0.01),
    EventType.AUTHENTICATION_FAILURE: (0.03, 0.01),
    EventType.TOKEN_ISSUED:           (0.03, 0.01),
    EventType.TOKEN_PRESENTED:        (0.02, 0.005),
    EventType.TOKEN_VALIDATED:        (0.02, 0.005),
    EventType.SESSION_OPENED:         (0.02, 0.005),
    EventType.ACCESS_REQUEST:         (0.1,  0.05),
    EventType.ACCESS_GRANTED:         (0.02, 0.005),
    EventType.ACCESS_DENIED:          (0.02, 0.005),
    EventType.SESSION_CLOSED:         (1.0,  0.5),
    EventType.RENEWAL_REQUEST:        (5.0,  2.0),
    EventType.TOKEN_EXPIRED:          (300.0, 10.0),
    EventType.RETRY:                  (0.2,  0.1),
    EventType.TIMEOUT:                (30.0, 5.0),
    EventType.DISCONNECT:             (1.0,  0.5),
}

TOKEN_CARRYING_EVENTS = {
    EventType.TOKEN_ISSUED, EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED, EventType.TOKEN_REJECTED,
    EventType.RENEWAL_REQUEST, EventType.SESSION_OPENED,
    EventType.ACCESS_REQUEST, EventType.ACCESS_GRANTED,
    EventType.ACCESS_DENIED,
}

NONCE_CARRYING_EVENTS = {
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
}

# Events that operate on an MQTT topic (session/authorization/access context).
TOPIC_CARRYING_EVENTS = {
    EventType.SESSION_OPENED,
    EventType.ACCESS_REQUEST, EventType.ACCESS_GRANTED, EventType.ACCESS_DENIED,
}

# Events that target a specific protected resource.
RESOURCE_CARRYING_EVENTS = {
    EventType.ACCESS_REQUEST, EventType.ACCESS_GRANTED, EventType.ACCESS_DENIED,
}

# OAuth2/ACE token scopes granted at issuance (one per session).
TOKEN_SCOPES = [
    "telemetry:read", "telemetry:readwrite", "telemetry:write", "config:read",
]

# Deterministic, benign steps that must never be flagged as a random transient
# failure. Registration (UNREGISTERED→REGISTERED and the idempotent
# REGISTERED→REGISTERED re-registration / confirmation) is always legitimate,
# so it should never produce a "transient_error" failure on a valid transition.
RELIABLE_EVENTS = {
    EventType.DISCOVERY,
    EventType.GATEWAY_ADVERTISEMENT,
    EventType.PAIRING_REQUEST,
    EventType.PAIRING_RESPONSE,
    EventType.ENROLLMENT_REQUEST,
    EventType.ENROLLMENT_CONFIRMED,
    EventType.REGISTRATION_REQUEST,
    EventType.REGISTRATION_CONFIRMED,
}

# ── Anomaly session continuation policy ───────────────────────────────────────
# Fraction of each anomaly type whose session RESUMES the legitimate flow after
# the injected event, instead of ending on the anomaly. Without this, every
# anomaly is truncated at the injection point and therefore never reaches
# SESSION_OPENED / ACCESS_GRANTED / SESSION_CLOSED — which turns those features
# (and n_events) into a perfect label shortcut.
#
# Only the "in-session" replay/renewal family continues: for these the anomaly
# is an extra/replayed event while an otherwise-working session proceeds. The
# identity / unauthorized / lockout attacks (impersonation, identity_token_
# mismatch, access_without_auth, abnormal_failure_rate) legitimately terminate
# on the anomaly, and their honest signals (identity_claim_mismatch,
# unauthorized_access_attempt, …) carry the discriminative information instead.
CONTINUE_AFTER_INJECTION: Dict[str, float] = {
    "replay_token":            0.60,
    "nonce_reuse":             0.60,
    "timestamp_inconsistency": 0.50,
    "abnormal_renewal":        0.70,
    "duplicate_sequence":      0.70,
    "impersonation":           0.0,
    "identity_token_mismatch": 0.0,
    "access_without_auth":     0.0,
    "abnormal_failure_rate":   0.0,
    "connect_flood":           0.0,   # flood terminates on the anomaly
    "delayed_connect":         0.0,   # half-open connect stalls / times out
}

# Realistic TCP handshake flag combinations observed at connection level.
# A completed connection almost always shows the full handshake regardless of
# whether the application-layer behaviour is malicious, so the distribution
# overlaps heavily between classes (only a mild skew toward half-open / reset
# for attacks). This avoids tcp_flags being a perfect discriminator.
_TCP_FLAG_CHOICES = ["SYN,ACK", "SYN,ACK,PSH", "SYN,ACK,FIN", "SYN", "SYN,ACK,RST"]

# Common MQTT keep-alive values (seconds). Same support for both classes so no
# single value is class-exclusive; attacks merely lean shorter.
_KEEP_ALIVE_CHOICES = [10, 15, 30, 60, 120, 300]

# Attack types where the pairing (ECDH) handshake itself is more likely to fail.
# Most attacks operate AFTER a successful pairing, so pairing usually succeeds
# for both classes.
_PAIRING_FAIL_PROB = {
    "impersonation":           0.35,
    "identity_token_mismatch": 0.30,
    "access_without_auth":     0.25,
    "connect_flood":           0.20,
    "delayed_connect":         0.30,
}


def _sample_tcp_flags(is_attack: bool) -> str:
    """Sample a TCP-flags combination that overlaps across classes."""
    weights = [58, 18, 8, 10, 6] if is_attack else [64, 22, 10, 3, 1]
    return random.choices(_TCP_FLAG_CHOICES, weights, k=1)[0]


def _sample_keep_alive(is_attack: bool) -> int:
    """Sample an MQTT keep-alive value from a shared, overlapping distribution."""
    weights = [12, 18, 22, 28, 12, 8] if is_attack else [4, 8, 20, 34, 20, 14]
    return random.choices(_KEEP_ALIVE_CHOICES, weights, k=1)[0]


def _sample_pairing_result(is_attack: bool, anomaly_type: Optional[str]) -> int:
    """Pairing succeeds for the vast majority of sessions in both classes."""
    if not is_attack:
        return 0 if random.random() < 0.03 else 1
    fail_prob = _PAIRING_FAIL_PROB.get(anomaly_type, 0.08)
    return 0 if random.random() < fail_prob else 1


# ── Traffic intensity (packet_rate / message_rate) ────────────────────────────
# Only genuinely traffic-intensive attacks raise the message / packet rate.
# Protocol-logic attacks (replay, nonce reuse, timestamp, identity, unauthorized
# access, abnormal renewal, impersonation) ride inside otherwise normal-looking
# traffic, so they must share the normal rate band — otherwise "high rate ⇒
# attack" becomes a trivial shortcut that hides the authentication-lifecycle
# signal we actually want models to learn.
RATE_BASED_ATTACKS = {
    "abnormal_failure_rate",   # brute-force / repeated auth hammering
    "duplicate_sequence",      # full auth sequence replayed → extra request volume
    "connect_flood",           # burst of MQTT CONNECT packets
}


def _sample_traffic_rate(is_rate_based: bool) -> Tuple[float, float]:
    """
    Return (packet_rate, message_rate) in msgs|packets per second.

    Baseline sessions (normal + protocol-logic attacks) draw from one shared
    low-to-moderate lognormal band; traffic-intensive attacks draw from a higher
    lognormal whose lower tail overlaps the top of the baseline band — so the
    two are NOT cleanly separable. packet_rate is derived from message_rate with
    noise (each MQTT message rides on ≥1 packet plus acks) so it overlaps too,
    instead of being an independent high-vs-low leak.
    """
    if is_rate_based:
        # median ~90 msg/s, heavy tail up to a few hundred (flood-like)
        msg_rate = random.lognormvariate(math.log(90.0), 0.85)
    else:
        # median ~2 msg/s, moderate tail into the low tens (bursty telemetry)
        msg_rate = random.lognormvariate(math.log(2.0), 1.0)
    msg_rate = min(max(msg_rate, 0.05), 600.0)

    packet_rate = max(0.1, msg_rate * random.uniform(1.5, 4.0)
                      + random.gauss(0.0, 1.0))
    return round(packet_rate, 3), round(msg_rate, 3)


def _compute_trust_score(ctx: Dict, renewals: int) -> float:
    """
    Continuous zero-trust score in [0, 1].

    Derived from the behavioural / identity / temporal signals ACTUALLY observed
    in the session (never from the ground-truth label), starting from a high
    baseline and degrading with each deviation present. Small Gaussian noise is
    added so the score is continuous instead of collapsing onto a handful of
    discrete values (the previous formula only reacted to auth failures and
    renewals, so every attack pinned to exactly 0.8).

    Because it reacts to observed traces, a stealthy anomaly that leaves little
    trace (e.g. a very fast nonce reuse) legitimately keeps a high, normal-
    looking score. That is realistic and keeps trust_score from becoming a
    label shortcut — it carries genuine, graded signal that still overlaps the
    normal band.
    """
    trust = 0.85

    # Repeated auth failures erode trust; successful renewals slightly restore it.
    trust -= 0.07 * ctx.get("failed_auth_count", 0)
    trust += 0.02 * renewals

    # Identity / credential deviations (impersonation, foreign token, no-auth access).
    trust -= 0.28 * ctx.get("identity_claim_mismatch", 0)
    trust -= 0.24 * ctx.get("token_device_mismatch", 0)
    trust -= 0.24 * ctx.get("unauthorized_access_attempt", 0)
    trust -= 0.14 * ctx.get("source_ip_change", 0)

    # Replay / duplication / scope violations.
    trust -= 0.18 * ctx.get("replay_window_violation", 0)
    trust -= 0.14 * ctx.get("duplicate_session_count", 0)
    trust -= 0.08 * ctx.get("topic_scope_violation", 0)

    # Graded temporal signals — magnitude drives within-type spread.
    trust -= 0.12 * min(ctx.get("timestamp_delta_s", 0.0) / 900.0, 1.0)
    trust -= 0.10 * min(ctx.get("token_age_at_replay", 0.0) / 600.0, 1.0)
    trust -= 0.10 * min(ctx.get("nonce_age_at_reuse", 0.0) / 60.0, 1.0)

    # Continuous jitter so the feature is a real distribution, not 3 spikes.
    trust += random.gauss(0.0, 0.06)

    return round(max(0.0, min(1.0, trust)), 3)


# ══════════════════════════════════════════════════════════════════════════════
# SessionContext — all Phase 0 features not derivable from AuthEvent alone
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionContext:
    """
    Device-level, network-level, MQTT-level, re-auth, and step-latency
    attributes generated alongside the AuthEvent sequence.

    Merged into the feature table by output_views.to_feature_df().
    
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    claimed_device_id:       str
    source_ip:               str
    registered_device:       int    # 1 = enrolled, 0 = unknown/forged
    source_connection_count: int
    source_diversity:        int    # distinct IPs seen for this device
    battery_level:           float

    # ── Network / pairing ─────────────────────────────────────────────────────
    tcp_flags:           str
    connection_duration: float   # ms — total TCP connection time
    tcp_rtt:             float   # ms
    packet_rate:         float   # packets/sec
    inter_arrival_time:  float   # ms between packets
    frame_length:        int     # bytes
    tcp_segment_len:     int     # bytes
    pairing_result:      int     # 1 = success
    pairing_latency_ms:  float

    # ── Enrollment & auth ─────────────────────────────────────────────────────
    credential_status:  int     # 1 = valid, 0 = forged/stolen
    mqtt_msg_type:      str     # "CONNECT"
    connect_flags:      int     # 0xC2
    clean_session:      int
    username_present:   int
    password_length:    int
    keep_alive:         int     # seconds
    mqtt_version:       int     # 5
    connack_code:       str     # "success" | failure reason
    auth_result:        int     # 1 = success
    auth_latency_ms:    float
    failed_auth_count:  int

    # ── Authorization / MQTT ──────────────────────────────────────────────────
    requested_topic:       str
    topic_length:          int
    operation:             str    # "pub_sub"
    requested_qos:         int
    granted_qos:           int
    authorization_result:  int    # 1 = granted
    topic_scope_violation: int    # 1 = topic outside allowed scope
    retain_flag:           int

    # ── MQTT session ──────────────────────────────────────────────────────────
    message_id:      int
    duplicate_flag:  int
    payload_length:  int     # bytes
    payload_hash:    str     # blake2s of sample payload
    qos_level:       int
    message_rate:    float   # msgs/sec
    byte_rate:       float   # bytes/sec
    session_duration: float  # seconds

    # ── Continuous re-auth / Zero Trust ───────────────────────────────────────
    trust_score:              float
    re_auth_required:         int
    gateway_decision:         str
    session_present:          int
    source_ip_change:         int
    replay_window_violation:  int
    behavior_deviation_score: float

    # ── Step latencies ────────────────────────────────────────────────────────
    s1_latency_ms: float   # discovery / registration
    s2_latency_ms: float   # pairing / challenge
    s3_latency_ms: float   # enrollment / auth result
    s4_latency_ms: float   # authorization / token issuance
    s5_latency_ms: float   # MQTT session open
    s6_latency_ms: float   # re-auth / renewal

    # ── Labels (Phase 0 naming) ───────────────────────────────────────────────
    attack_type:   str   # "normal" | anomaly_label
    attack_phase:  str   # event_type of injected anomaly | "none"
    severity:      str   # none | medium | high | critical
    attacker_class: str  # none | non_invasive | invasive | both

    # ── Phase 4: per-variant replay signals (default 0 for non-replay sessions) ─
    token_age_at_replay:     float = 0.0  # replay_token: seconds since token was issued
    nonce_age_at_reuse:      float = 0.0  # nonce_reuse: seconds since challenge was sent
    timestamp_delta_s:       float = 0.0  # timestamp_inconsistency: backward-jump magnitude
    duplicate_session_count: int   = 0    # duplicate_sequence: number of replayed sequences

    # ── Phase 5: identity / session anomaly signals ───────────────────────────
    identity_claim_mismatch:    int = 0   # impersonation: claimed_id != device_id
    token_device_mismatch:      int = 0   # identity_token_mismatch: foreign token used
    unauthorized_access_attempt: int = 0  # access_without_auth: ACCESS_REQUEST before auth
    steps_before_access:        int = 0   # access_without_auth: auth steps completed before attempt

    # ── Flooding / protocol-abuse signals (default 0 for non-flood sessions) ──
    connection_burst_count: int   = 0     # connect_flood: CONNECTs in the burst window
    stall_duration_s:       float = 0.0   # delayed_connect: half-open hold time

    def to_dict(self) -> dict:
        return asdict(self)


# ══════════════════════════════════════════════════════════════════════════════
# EventEngine
# ══════════════════════════════════════════════════════════════════════════════

class EventEngine:
    """
    Executes one ScenarioSpec into (List[AuthEvent], SessionContext).

    Parameters
    ----------
    device_id       : carried on every AuthEvent
    gateway_id      : carried on every AuthEvent
    auth_server_id  : carried on every AuthEvent
    broker_id       : optional MQTT broker id
    source_ip       : device source IP (default: sampled from 10.0.1.x)
    battery_level   : device battery % (default: uniform 0–100)
    start_time      : Unix timestamp for first event (default: now)
    """

    def __init__(
        self,
        device_id:        str,
        gateway_id:       str,
        auth_server_id:   str,
        broker_id:        Optional[str]   = None,
        source_ip:        Optional[str]   = None,
        battery_level:    Optional[float] = None,
        firmware_version: Optional[str]   = None,
        start_time:       Optional[float] = None,
        driver:           object          = None,
    ):
        self.device_id        = device_id
        self.gateway_id       = gateway_id
        self.auth_server_id   = auth_server_id
        self.broker_id        = broker_id
        # Phase C: optional SessionDriver that drives the real domain entities.
        # None → pure synthesised generation (default, unchanged behaviour).
        self.driver           = driver
        self.source_ip        = source_ip or f"10.0.1.{random.randint(1, 254)}"
        self.battery_level    = battery_level if battery_level is not None \
                                else round(random.uniform(0.0, 100.0), 1)
        self.firmware_version = firmware_version or random.choice(
            cfg.device.firmware_versions
        )
        self.start_time       = start_time or time.time()

    # ══════════════════════════════════════════════════════════════════════════
    # Main entry point
    # ══════════════════════════════════════════════════════════════════════════

    def execute(self, spec: ScenarioSpec) -> Tuple[List[AuthEvent], SessionContext]:
        """
        Execute one ScenarioSpec.

        Returns
        -------
        (events, context)
          events  : correlated AuthEvent sequence
          context : SessionContext with all Phase 0 features
        """
        sm         = StateMachine()
        events:    List[AuthEvent] = []
        session_id = str(uuid.uuid4())
        is_attack  = spec.is_anomaly
        profile    = DELAY_PROFILE_ATTACK if is_attack else DELAY_PROFILE_NORMAL

        # ── Session-level MQTT / token context (one value per session) ─────────
        topic:        str = f"iot/{self.device_id[:8]}/telemetry"
        resource_id:  str = f"resource://{self.device_id[:8]}/telemetry"
        token_scope:  str = random.choice(TOKEN_SCOPES)

        # Phase 3 — temporal tracker for this session
        te = TemporalEngine(config=TemporalConfig(), is_attack=is_attack)

        # ── Mutable run-state threaded through every step (see _run_step) ──────
        rs: Dict = {
            "current_ts":   self.start_time,
            "token_id":     None,          # set once a token is issued
            "token_expiry": None,
            "nonce":        None,
            "retry_count":  0,
            "session_id":   session_id,
            "topic":        topic,
            "resource_id":  resource_id,
            "token_scope":  token_scope,
        }

        # ── Accumulators for SessionContext ───────────────────────────────────
        ctx: Dict = {
            "s1_latency_ms": 0.0, "s2_latency_ms": 0.0,
            "s3_latency_ms": 0.0, "s4_latency_ms": 0.0,
            "s5_latency_ms": 0.0, "s6_latency_ms": 0.0,
            "auth_latency_ms":       0.0,
            "pairing_latency_ms":    0.0,
            "auth_result":           0,
            "final_auth_result":     0,   # set by last AUTH_SUCCESS seen
            "credential_status":     1,
            "connack_code":          "pending",
            "failed_auth_count":     0,
            "authorization_result":  0,
            "topic_scope_violation": 0,
            "re_auth_required":      0,
            "source_ip_change":      0,
            "session_present":       0,
            "replay_window_violation": 0,
            # retry tracking
            "n_retries_fired":       0,
            # Phase 4: per-variant replay signals
            "token_age_at_replay":      0.0,
            "nonce_age_at_reuse":       0.0,
            "timestamp_delta_s":        0.0,
            "duplicate_session_count":  0,
            # Phase 5: identity / session anomaly signals
            "identity_claim_mismatch":    0,
            "token_device_mismatch":      0,
            "unauthorized_access_attempt": 0,
            "steps_before_access":        0,
            # Flooding / protocol-abuse signals
            "connection_burst_count":     0,
            "stall_duration_s":           0.0,
        }

        # ── Run normal steps ──────────────────────────────────────────────────
        steps_to_run = (
            spec.normal_steps[:spec.injection_position]
            if spec.is_anomaly else spec.normal_steps
        )

        for event_type in steps_to_run:
            self._run_step(event_type, sm, rs, ctx, te, events, profile, spec)

        # ── Anomaly injection ─────────────────────────────────────────────────
        if spec.is_anomaly:
            delay          = self._sample_delay(spec.injection_event, profile)
            rs["current_ts"] += delay

            # ── Phase 4: per-variant enrichment before state machine step ────────

            # replay_token: token presented well outside the allowed replay window
            if spec.anomaly_type == "replay_token":
                stolen_age = random.uniform(120, 600)
                te.record_token_issued(rs["current_ts"] - stolen_age)
                te.record_token_presented(rs["current_ts"])
                ctx["replay_window_violation"] = 1
                ctx["token_age_at_replay"]     = round(stolen_age, 2)

            # nonce_reuse: reuse the existing nonce value so n_nonce_reuses > 0
            # nonce stays as-is — we deliberately do NOT generate a new one here.
            # The same value will appear on both the original NONCE_RECEIVED event
            # and this injected event, making output_views count it as a reuse.
            if spec.anomaly_type == "nonce_reuse" and rs["nonce"] is not None:
                ctx["nonce_age_at_reuse"] = round(te.nonce_age(rs["current_ts"]), 2)

            # timestamp_inconsistency: record the backward-jump magnitude before applying
            if spec.anomaly_type == "timestamp_inconsistency":
                delta            = random.uniform(400, 900)
                rs["current_ts"] = rs["current_ts"] - delta
                ctx["timestamp_delta_s"] = round(delta, 2)

            # duplicate_sequence: a complete auth sequence replayed inside open session
            if spec.anomaly_type == "duplicate_sequence":
                ctx["duplicate_session_count"] = 1

            # connect_flood: a burst of MQTT CONNECT packets with invalid creds
            if spec.anomaly_type == "connect_flood":
                burst = cfg.attack.dos_connection_burst
                ctx["connection_burst_count"] = random.randint(burst, burst * 4)
                ctx["credential_status"]      = 0

            # delayed_connect: TCP handshake done, then the client stalls before
            # sending CONNECT — model the hold time and push the timeout out.
            if spec.anomaly_type == "delayed_connect":
                stall = max(1.0, random.gauss(cfg.attack.delayed_connect_stall_s,
                                              cfg.attack.delayed_connect_stall_s * 0.4))
                rs["current_ts"]             += stall
                ctx["stall_duration_s"]       = round(stall, 2)
                ctx["connection_burst_count"] = 1

            # State the legitimate flow had reached before the injection — the
            # continuation (below) resumes from here so the session can complete.
            pre_injection_state = sm.state
            sm.force(spec.injection_from_state)

            try:
                sm.advance(spec.injection_event)
                new_state = sm.state
            except TransitionError:
                new_state = spec.injection_from_state

            identity_claim = None

            # ── Phase 5: identity / session anomaly enrichment ────────────────

            if spec.anomaly_type == "impersonation":
                identity_claim                   = f"victim-{str(uuid.uuid4())[:8]}"
                ctx["source_ip_change"]          = 1
                ctx["credential_status"]         = 0
                ctx["identity_claim"]            = identity_claim
                ctx["identity_claim_mismatch"]   = 1   # claimed_id != device_id

            elif spec.anomaly_type == "identity_token_mismatch":
                # Attacker presents a token issued for a *different* device.
                # Overwrite token_id with a foreign one so it never matches
                # the token that was (or would have been) issued in this session.
                rs["token_id"]                 = f"foreign-{str(uuid.uuid4())}"
                identity_claim                 = f"victim-{str(uuid.uuid4())[:8]}"
                ctx["identity_claim"]          = identity_claim
                ctx["credential_status"]       = 0
                ctx["token_device_mismatch"]   = 1
                ctx["identity_claim_mismatch"] = 1

            elif spec.anomaly_type == "access_without_auth":
                # Device tries to access a resource before any auth has completed.
                ctx["credential_status"]              = 0  # no auth = no valid credential
                ctx["unauthorized_access_attempt"]    = 1
                ctx["steps_before_access"]            = spec.injection_position

            if spec.anomaly_type in {"replay_token"}:
                ctx["credential_status"] = 0

            # For nonce_reuse injection: carry the original nonce so output_views
            # detects the duplicate (same nonce value on two distinct events).
            injected_nonce = (
                rs["nonce"]
                if spec.anomaly_type == "nonce_reuse"
                else (rs["nonce"] if spec.injection_event in NONCE_CARRYING_EVENTS else None)
            )

            inj_token_id = rs["token_id"] if spec.injection_event in TOKEN_CARRYING_EVENTS else None
            ev = self._make_event(
                event_type=spec.injection_event, prev_state=spec.injection_from_state,
                new_state=new_state, result=EventResult.FAILURE,
                failure_reason=f"invalid_transition_{spec.anomaly_type}",
                session_id=session_id, scenario_id=spec.scenario_id,
                timestamp=rs["current_ts"], delay=delay, retry_count=rs["retry_count"],
                token_id=inj_token_id,
                token_expiry=rs["token_expiry"] if inj_token_id else None,
                token_scope=token_scope if inj_token_id else None,
                nonce=injected_nonce,
                topic=topic if spec.injection_event in TOPIC_CARRYING_EVENTS else None,
                resource_id=resource_id if spec.injection_event in RESOURCE_CARRYING_EVENTS else None,
                anomaly_label=spec.anomaly_type,
                identity_claim=identity_claim,
            )
            events.append(ev)

            # ── Continuation: resume the legitimate flow for a fraction of the
            # in-session replay/renewal anomalies so they can still reach
            # SESSION_OPENED / ACCESS_GRANTED / SESSION_CLOSED and overlap normal
            # sessions on n_events (breaking those as label shortcuts). ─────────
            if (spec.injection_position < len(spec.normal_steps)
                    and random.random() < CONTINUE_AFTER_INJECTION.get(spec.anomaly_type, 0.0)):
                sm.force(pre_injection_state)
                for event_type in spec.normal_steps[spec.injection_position:]:
                    self._run_step(event_type, sm, rs, ctx, te, events, profile, spec)

        # ── Final auth_result reflects the accumulated state (post-continuation) ─
        ctx["auth_result"] = ctx["final_auth_result"]

        # ── Build SessionContext ───────────────────────────────────────────────
        context = self._build_context(spec, events, ctx, te)
        return events, context

    # ══════════════════════════════════════════════════════════════════════════
    # Single-step executor (one AuthEvent from one EventType)
    # ══════════════════════════════════════════════════════════════════════════

    def _run_step(
        self,
        event_type: EventType,
        sm:         StateMachine,
        rs:         Dict,
        ctx:        Dict,
        te:         "TemporalEngine",
        events:     List[AuthEvent],
        profile:    Dict[EventType, Tuple[float, float]],
        spec:       ScenarioSpec,
    ) -> None:
        """
        Execute one legitimate flow step: advance the state machine, update the
        shared token/nonce/latency context (rs / ctx), and append the AuthEvent.

        Used for both the pre-injection steps and the optional post-injection
        continuation, so every completed session — normal or anomalous — goes
        through exactly the same event-construction path.
        """
        # Phase 3: use retry backoff delay for RETRY events
        if event_type == EventType.RETRY:
            delay = te.next_retry_delay()
        else:
            delay = self._sample_delay(event_type, profile)
        rs["current_ts"] += delay
        prev_state = sm.state
        result, failure_reason = self._outcome(event_type, is_anomaly=False)

        try:
            new_state = sm.advance(event_type)
        except TransitionError:
            new_state      = prev_state
            result         = EventResult.FAILURE
            failure_reason = "unexpected_transition_error"

        # ── Update shared token/nonce context ─────────────────────────────────
        if event_type == EventType.TOKEN_ISSUED:
            rs["token_id"]     = str(uuid.uuid4())
            rs["token_expiry"] = rs["current_ts"] + cfg.security.token_lifetime_s
            te.record_token_issued(rs["current_ts"])         # Phase 3
        if event_type == EventType.RENEWAL_REQUEST:
            # Renewal extends the token's lifetime from the renewal moment.
            rs["token_expiry"] = rs["current_ts"] + cfg.security.token_lifetime_s
        if event_type == EventType.TOKEN_PRESENTED:
            te.record_token_presented(rs["current_ts"])      # Phase 3
        if event_type == EventType.CHALLENGE_SENT:
            rs["nonce"] = hashlib.blake2s(uuid.uuid4().bytes).hexdigest()[:16]
            te.record_nonce_issued(rs["current_ts"])         # Phase 3
        if event_type in {EventType.AUTHENTICATION_FAILURE, EventType.TOKEN_REJECTED}:
            rs["retry_count"]        += 1
            ctx["failed_auth_count"] += 1
            te.record_failure()                              # Phase 3
        if event_type == EventType.RETRY:
            ctx["n_retries_fired"] += 1

        # ── Phase C: drive the real domain entities (flag-gated; no-op if None) ─
        # Exercises ECDH / enrollment / token issuance / broker sessions on the
        # core/ objects. Only override is the real token id at issuance; all
        # leakage-tuned feature values are left untouched.
        if self.driver is not None:
            overrides = self.driver.on_event(event_type, rs, rs["current_ts"])
            if overrides:
                rs.update(overrides)

        # ── Capture step latencies (mapped to the six lifecycle phases) ───────
        delay_ms = delay * 1000
        if event_type in (EventType.DISCOVERY, EventType.REGISTRATION_REQUEST):
            # s1 = discovery / registration
            ctx["s1_latency_ms"] = round(delay_ms, 2)
        elif event_type == EventType.PAIRING_RESPONSE:
            # pairing latency = the ECDH exchange step
            ctx["pairing_latency_ms"] = round(delay_ms, 2)
        elif event_type == EventType.CHALLENGE_SENT and ctx["s2_latency_ms"] == 0.0:
            # s2 = pairing / challenge — capture only the first challenge
            # (retry and renewal scenarios issue more than one)
            ctx["s2_latency_ms"] = round(delay_ms, 2)
            if ctx["pairing_latency_ms"] == 0.0:
                ctx["pairing_latency_ms"] = round(delay_ms, 2)
        elif event_type == EventType.AUTHENTICATION_SUCCESS:
            ctx["s3_latency_ms"]      = round(delay_ms, 2)
            ctx["auth_latency_ms"]    = round(delay_ms, 2)
            ctx["final_auth_result"]  = 1
            ctx["connack_code"]       = "success"
            ctx["credential_status"]  = 1
        elif event_type == EventType.AUTHENTICATION_FAILURE:
            # Only update s3 if we haven't succeeded yet
            if ctx["final_auth_result"] == 0:
                ctx["s3_latency_ms"]   = round(delay_ms, 2)
                ctx["auth_latency_ms"] = round(delay_ms, 2)
            ctx["connack_code"] = failure_reason or "auth_failure"
        elif event_type == EventType.TOKEN_ISSUED and ctx["s4_latency_ms"] == 0.0:
            ctx["s4_latency_ms"] = round(delay_ms, 2)
        elif event_type == EventType.SESSION_OPENED:
            ctx["s5_latency_ms"]        = round(delay_ms, 2)
            ctx["authorization_result"] = 1
            ctx["session_present"]      = 1
        elif event_type == EventType.RENEWAL_REQUEST:
            ctx["s6_latency_ms"]    = round(delay_ms, 2)
            ctx["re_auth_required"] = 1
            te.record_renewal(rs["current_ts"])              # Phase 3: reset token clock
        elif event_type == EventType.ACCESS_DENIED:
            ctx["topic_scope_violation"] = 1 if random.random() < 0.3 else 0

        ev_token_id = rs["token_id"] if event_type in TOKEN_CARRYING_EVENTS else None
        ev = self._make_event(
            event_type=event_type, prev_state=prev_state,
            new_state=new_state, result=result,
            failure_reason=failure_reason, session_id=rs["session_id"],
            scenario_id=spec.scenario_id, timestamp=rs["current_ts"],
            delay=delay, retry_count=rs["retry_count"],
            token_id=ev_token_id,
            token_expiry=rs["token_expiry"] if ev_token_id else None,
            token_scope=rs["token_scope"] if ev_token_id else None,
            nonce=rs["nonce"] if event_type in NONCE_CARRYING_EVENTS else None,
            topic=rs["topic"] if event_type in TOPIC_CARRYING_EVENTS else None,
            resource_id=rs["resource_id"] if event_type in RESOURCE_CARRYING_EVENTS else None,
            anomaly_label=None,
        )
        events.append(ev)

    # ══════════════════════════════════════════════════════════════════════════
    # SessionContext builder
    # ══════════════════════════════════════════════════════════════════════════

    def _build_context(
        self,
        spec:   ScenarioSpec,
        events: List[AuthEvent],
        ctx:    Dict,
        te:     Optional["TemporalEngine"] = None,
    ) -> SessionContext:
        is_attack   = spec.is_anomaly
        # Phase 3 fix: use the actual anomaly label, not a generic "attack" string
        attack_type = spec.anomaly_type if is_attack else "normal"

        # Traffic intensity depends on the attack TYPE, not the label: only
        # genuinely rate-based attacks flood; protocol-logic attacks share the
        # normal rate band (see _sample_traffic_rate / RATE_BASED_ATTACKS).
        is_rate_based        = is_attack and attack_type in RATE_BASED_ATTACKS
        pkt_rate, msg_rate   = _sample_traffic_rate(is_rate_based)

        # ── Network features ──────────────────────────────────────────────────
        if is_attack:
            tcp_rtt    = max(1.0, random.gauss(8.0,  30.0))
        else:
            tcp_rtt    = max(1.0, random.gauss(20.0, 5.0))

        inter_arrival = round(1000.0 / pkt_rate, 2)
        frame_len     = random.randint(64, 256)
        seg_len       = random.randint(128, 512)
        conn_duration = round((events[-1].timestamp - events[0].timestamp) * 1000, 2)

        # ── MQTT features ─────────────────────────────────────────────────────
        qos_level    = random.choice([0, 1, 2])
        topic        = f"iot/{self.device_id[:8]}/telemetry"
        payload_size = (
            random.randint(512, 8192) if is_attack
            else random.randint(10, 512)
        )
        payload_sample = bytes(random.randint(0, 255) for _ in range(min(payload_size, 64)))
        payload_hash   = hashlib.blake2s(payload_sample).hexdigest()

        # keep_alive: sampled from a shared, overlapping distribution (no longer
        # a hard 10-vs-60 split that perfectly separates the classes).
        # message_rate was sampled above (with packet_rate) from the type-aware
        # traffic profile so it overlaps between normal and non-rate attacks.
        keep_alive = _sample_keep_alive(is_attack)

        byte_rate = round(msg_rate * payload_size, 2)

        mqtt_types = [
            "CONNECT", "CONNACK", "PUBLISH", "PUBACK",
            "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE", "UNSUBACK",
            "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH",
        ]
        if is_attack:
            weights = [1, 1, 5, 1, 1, 1, 1, 1, 1, 1, 2, 1]
        else:
            weights = [2, 1, 6, 1, 1, 1, 1, 1, 1, 1, 1, 0.5]
        mqtt_msg_type = random.choices(mqtt_types, weights, k=1)[0]

        if mqtt_msg_type == "CONNECT":
            connect_flags    = 0xC2
            clean_session    = 1
            username_present = 1
            password_length  = 64
        else:
            connect_flags    = 0
            clean_session    = 0
            username_present = 0
            password_length  = 0

        operation = "publish" if mqtt_msg_type == "PUBLISH" else "pub_sub"

        session_dur = max(0.0, events[-1].timestamp - events[0].timestamp)

        # ── Trust score — continuous zero-trust score from observed signals ─────
        renewals = te.renewal_count if te else 0
        trust = _compute_trust_score(ctx, renewals)
        replay_viol = ctx.get("replay_window_violation", 0)
        behavior_dev = round(
            (1.0 - trust)
            + 0.3 * ctx["source_ip_change"]
            + 0.4 * replay_viol,
            3
        )

        # ── Gateway decision ──────────────────────────────────────────────────
        if ctx["re_auth_required"]:
            gw_decision = "reauth_required"
        elif ctx["source_ip_change"]:
            gw_decision = "ip_change_detected"
        elif replay_viol:
            gw_decision = "replay_detected"
        else:
            gw_decision = "session_valid"

        # ── Claimed device id ─────────────────────────────────────────────────
        claimed_id = ctx.get("identity_claim", self.device_id)

        # ── Attack labels (Phase 3 fix: correct type + SEVERITY_MAP) ──────────
        attack_phase   = spec.injection_event.value if is_attack else "none"
        severity       = SEVERITY_MAP.get(spec.anomaly_type, "none") if is_attack else "none"
        attacker_class = ATTACKER_CLASS_MAP.get(spec.anomaly_type, "none") if is_attack else "none"

        return SessionContext(
            # Identity
            claimed_device_id       = claimed_id,
            source_ip               = self.source_ip,
            registered_device       = ctx["credential_status"],
            source_connection_count = random.randint(1, 10),
            source_diversity        = 1 + ctx["source_ip_change"],
            battery_level           = self.battery_level,
            # Network
            tcp_flags               = _sample_tcp_flags(is_attack),
            connection_duration     = conn_duration,
            tcp_rtt                 = round(tcp_rtt, 2),
            packet_rate             = round(pkt_rate, 3),
            inter_arrival_time      = inter_arrival,
            frame_length            = frame_len,
            tcp_segment_len         = seg_len,
            pairing_result          = _sample_pairing_result(is_attack, attack_type),
            pairing_latency_ms      = ctx["pairing_latency_ms"],
            # Auth / MQTT
            credential_status       = ctx["credential_status"],
            mqtt_msg_type           = mqtt_msg_type,
            connect_flags           = connect_flags,
            clean_session           = clean_session,
            username_present        = username_present,
            password_length         = password_length,
            keep_alive              = keep_alive,
            mqtt_version            = 5,
            connack_code            = ctx["connack_code"],
            auth_result             = ctx["auth_result"],
            auth_latency_ms         = ctx["auth_latency_ms"],
            failed_auth_count       = ctx["failed_auth_count"],
            # Authorization
            requested_topic         = topic,
            topic_length            = len(topic),
            operation               = operation,
            requested_qos           = qos_level,
            granted_qos             = qos_level,
            authorization_result    = ctx["authorization_result"],
            topic_scope_violation   = ctx["topic_scope_violation"],
            retain_flag             = 1 if mqtt_msg_type == "PUBLISH" and random.random() < 0.1 else 0,
            # MQTT session
            message_id              = random.randint(1, 65535),
            duplicate_flag          = 0,
            payload_length          = payload_size if mqtt_msg_type == "PUBLISH" else 0,
            payload_hash            = payload_hash if mqtt_msg_type == "PUBLISH" else "",
            qos_level               = qos_level,
            message_rate            = round(msg_rate, 3),
            byte_rate               = byte_rate,
            session_duration        = round(session_dur, 3),
            # Re-auth
            trust_score             = round(trust, 3),
            re_auth_required        = ctx["re_auth_required"],
            gateway_decision        = gw_decision,
            session_present         = ctx["session_present"],
            source_ip_change        = ctx["source_ip_change"],
            replay_window_violation = replay_viol,
            behavior_deviation_score = min(behavior_dev, 1.0),
            # Step latencies
            s1_latency_ms           = ctx["s1_latency_ms"],
            s2_latency_ms           = ctx["s2_latency_ms"],
            s3_latency_ms           = ctx["s3_latency_ms"],
            s4_latency_ms           = ctx["s4_latency_ms"],
            s5_latency_ms           = ctx["s5_latency_ms"],
            s6_latency_ms           = ctx["s6_latency_ms"],
            # Labels
            attack_type             = attack_type,
            attack_phase            = attack_phase,
            severity                = severity,
            attacker_class          = attacker_class,
            # Phase 4: replay variant signals
            token_age_at_replay     = ctx.get("token_age_at_replay",     0.0),
            nonce_age_at_reuse      = ctx.get("nonce_age_at_reuse",      0.0),
            timestamp_delta_s       = ctx.get("timestamp_delta_s",       0.0),
            duplicate_session_count = ctx.get("duplicate_session_count", 0),
            # Phase 5: identity / session anomaly signals
            identity_claim_mismatch     = ctx.get("identity_claim_mismatch",     0),
            token_device_mismatch       = ctx.get("token_device_mismatch",       0),
            unauthorized_access_attempt = ctx.get("unauthorized_access_attempt", 0),
            steps_before_access         = ctx.get("steps_before_access",         0),
            # Flooding / protocol-abuse signals
            connection_burst_count      = ctx.get("connection_burst_count",      0),
            stall_duration_s            = ctx.get("stall_duration_s",            0.0),
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _make_event(
        self,
        event_type:     EventType,
        prev_state:     AuthState,
        new_state:      AuthState,
        result:         EventResult,
        failure_reason: Optional[str],
        session_id:     str,
        scenario_id:    str,
        timestamp:      float,
        delay:          float,
        retry_count:    int,
        token_id:       Optional[str],
        nonce:          Optional[str],
        anomaly_label:  Optional[str],
        identity_claim: Optional[str]   = None,
        token_expiry:   Optional[float] = None,
        token_scope:    Optional[str]   = None,
        topic:          Optional[str]   = None,
        resource_id:    Optional[str]   = None,
    ) -> AuthEvent:
        return AuthEvent(
            event_type                 = event_type,
            device_id                  = self.device_id,
            gateway_id                 = self.gateway_id,
            auth_server_id             = self.auth_server_id,
            broker_id                  = self.broker_id,
            previous_state             = prev_state,
            new_state                  = new_state,
            result                     = result,
            failure_reason             = failure_reason,
            session_id                 = session_id,
            scenario_id                = scenario_id,
            timestamp                  = timestamp,
            delay_since_previous_event = delay,
            token_id                   = token_id,
            token_expiry               = token_expiry,
            token_scope                = token_scope,
            nonce                      = nonce,
            retry_count                = retry_count,
            topic                      = topic,
            resource_id                = resource_id,
            firmware_version           = self.firmware_version,
            anomaly_label              = anomaly_label,
            identity_claim             = identity_claim,
            source_context             = "attack" if anomaly_label else "normal",
        )

    @staticmethod
    def _sample_delay(
        event_type: EventType,
        profile:    Dict[EventType, Tuple[float, float]],
    ) -> float:
        mean, std = profile.get(event_type, (0.1, 0.05))
        return max(0.0, random.gauss(mean, std))

    @staticmethod
    def _outcome(event_type: EventType, is_anomaly: bool) -> Tuple[EventResult, Optional[str]]:
        failure_events = {
            EventType.AUTHENTICATION_FAILURE,
            EventType.TOKEN_REJECTED,
            EventType.ACCESS_DENIED,
        }
        if event_type in failure_events:
            return EventResult.FAILURE, event_type.value
        # Registration is deterministic and benign — exempt it from the random
        # transient failure so a legitimate REGISTERED→REGISTERED transition is
        # never mislabelled as a failure.
        if (event_type not in RELIABLE_EVENTS
                and not is_anomaly and random.random() < 0.02):
            return EventResult.FAILURE, "transient_error"
        return EventResult.SUCCESS, None