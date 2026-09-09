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
  Consistency  — device, trace, authentication-attempt, protected-session,
                 token, and nonce relationships are carried explicitly
"""

import hashlib
import math
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from simulator.config.settings import cfg
from simulator.anomaly_contract import (
    InjectionRecord,
    SYNCHRONIZED_GENERATION_PROFILE,
    VARIANT_CAPABILITIES,
    VariantCapabilityStatus,
)
from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.state_machine import StateMachine, TransitionError
from simulator.engines.scenario_engine import REGISTRATION_PHASE, ScenarioSpec
from simulator.engines.temporal_engine import TemporalEngine, TemporalConfig
from simulator.security_context import (
    AuthenticationSessionContext,
    AuthenticationResult,
    AuthorizationDecision,
    PersistentDeviceContext,
    ReferenceAuthorizationPolicy,
    ResourceOperationOutcome,
    TokenValidationResult,
)
from simulator.semantic_time import SEMANTIC_TIME_DOMAIN, SemanticClock


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
    "normal":                   "none",
}

# ── Delay profile (mean, std) in seconds ──────────────────────────────────────
# SINGLE, label-independent timing profile for every session.
#
# Per-event protocol delays (pairing/ECDH cost, challenge-response, auth, MQTT
# session open, …) are network/compute costs of the *legitimate* protocol steps
# and have no physical reason to differ between benign and malicious sessions.
# The previous design used a separate, uniformly-faster DELAY_PROFILE_ATTACK,
# which made every attack's delays / step-latencies near-zero by construction —
# turning mean_delay_s, min/max_delay_s and every sX_latency_ms into a perfect
# label shortcut (ROC-AUC 0.90-0.96). Genuine timing anomalies are still carried
# by the honest signal columns (token_age_at_replay, nonce_age_at_reuse,
# timestamp_delta_s), not by systematically shrinking the whole session's delays.
DELAY_PROFILE: Dict[EventType, Tuple[float, float]] = {
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
    # Explicit semantic outcomes must not be renamed into contradictions by a
    # random transient failure. Benign failure paths use their explicit events.
    EventType.AUTHENTICATION_SUCCESS,
    EventType.TOKEN_ISSUED,
    EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED,
    EventType.SESSION_OPENED,
    EventType.ACCESS_GRANTED,
    EventType.SESSION_CLOSED,
    EventType.TIMEOUT,
    EventType.DISCONNECT,
}

# A synchronized ScenarioSpec is an explicit semantic sequence.  Its positive
# prerequisite steps cannot be assigned an unmodelled random ``transient_error``
# and then followed as though they succeeded: doing so leaves the legacy FSM
# behind the declared sequence and creates contradictory downstream evidence.
# Explicit negative events (AUTHENTICATION_FAILURE / TOKEN_REJECTED /
# ACCESS_DENIED) and the retry scenario continue to represent benign failure.
# Keep this synchronized-only so the frozen historical generation profile
# remains available as implementation evidence.
SYNCHRONIZED_RELIABLE_PREREQUISITES = {
    EventType.AUTHENTICATION_REQUEST,
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.RENEWAL_REQUEST,
    EventType.ACCESS_REQUEST,
    EventType.RETRY,
}

# These events communicate a negative semantic outcome while legitimately
# advancing the legacy FSM into the corresponding failure/denial context.
NEGATIVE_OUTCOME_TRANSITIONS = {
    EventType.AUTHENTICATION_FAILURE,
    EventType.TOKEN_REJECTED,
    EventType.ACCESS_DENIED,
}

AUTHENTICATION_INTERACTION_EVENTS = {
    EventType.AUTHENTICATION_REQUEST,
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.AUTHENTICATION_SUCCESS,
    EventType.AUTHENTICATION_FAILURE,
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
}

# ── Detection realism: stealth (false negatives) & benign triggers (false pos) ─
# Without these, every attack sets at least one deterministic detector flag
# (identity_claim_mismatch, replay_window_violation, …) and every normal sets
# none, so the union of those flags == is_anomaly and ANY classifier scores ~100%
# — unrealistic. These two knobs reintroduce the overlap real IDS datasets have.
#
# STEALTH_FRACTION[type] = fraction of that attack type that EVADES detection:
# the session is a genuine attack (is_anomaly stays 1) but leaves no explicit
# detector signal — the injected event is accepted (no invalid-transition
# failure, no forced state-jump), the per-type flags keep their benign defaults,
# and rate-based traffic is not elevated. Such sessions are (near-)
# indistinguishable from normal traffic → irreducible false negatives that cap
# recall below 1. Protocol-logic attacks (replay/nonce/timestamp) are stealthier
# than loud identity/flooding attacks. Raise these to make detection harder.
# Operating point: HALF stealth — chosen to give a strong-but-believable LR
# result (F1 ~0.95, recall ~0.92) without returning to the perfectly-separable
# regime. Double these values (0.25/0.20/0.15/0.10) for the harder, more
# realistic setting, or set to ~0 for the (too-perfect) no-evasion regime.
STEALTH_FRACTION: Dict[str, float] = {
    "replay_token":            0.125,
    "nonce_reuse":             0.125,
    "timestamp_inconsistency": 0.125,
    "duplicate_sequence":      0.10,
    "abnormal_renewal":        0.10,
    "impersonation":           0.075,
    "identity_token_mismatch": 0.075,
    "access_without_auth":     0.05,
    "abnormal_failure_rate":   0.05,
}
DEFAULT_STEALTH = 0.075

# Fraction of NORMAL sessions that exhibit a benign-but-suspicious condition
# (a roaming device changing source IP, a flaky link causing extra auth
# retries) without being an attack → false positives that cap precision below 1.
FALSE_POSITIVE_FRACTION = 0.06

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
    Historical one-row-per-trace feature context generated alongside the event
    sequence.  Despite its legacy name, this object is not the protected
    session security context; C1.2 identifiers below refer to that context
    explicitly.

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
    attack_type:  str   # "normal" | anomaly_label
    attack_phase: str   # event_type of injected anomaly | "none"
    severity:     str   # none | medium | high | critical

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

    # ── C1.2 semantic identifiers and persistence references ────────────────
    device_id:                  str = ""
    trace_id:                   str = ""
    scenario_id:                str = ""
    legacy_session_id:          str = ""
    protected_session_id:       Optional[str] = None
    auth_attempt_ids:           Tuple[str, ...] = field(default_factory=tuple)
    renewal_auth_attempt_ids:   Tuple[str, ...] = field(default_factory=tuple)
    refreshes_protected_session_id: Optional[str] = None
    persistent_enrolled:        bool = False
    persistent_paired:          bool = False
    authentication_result_semantic: str = AuthenticationResult.NOT_EVALUATED.value
    last_authentication_attempt_result: str = AuthenticationResult.NOT_EVALUATED.value
    authenticated_identity:     Optional[str] = None
    authenticated_context_active: bool = False
    token_validation_result:    str = TokenValidationResult.NOT_EVALUATED.value
    token_context_active:       bool = False
    protected_session_active:   bool = False
    requested_action:           Optional[str] = None
    authorization_decision:     str = AuthorizationDecision.NOT_EVALUATED.value
    resource_operation_outcome: str = ResourceOperationOutcome.NOT_EXECUTED.value
    access_request_ids:         Tuple[str, ...] = field(default_factory=tuple)
    authorization_decisions:    Tuple[str, ...] = field(default_factory=tuple)
    resource_operation_outcomes: Tuple[str, ...] = field(default_factory=tuple)
    semantic_time_domain:        str = SEMANTIC_TIME_DOMAIN
    trace_started_at:            Optional[float] = None
    trace_ended_at:              Optional[float] = None
    token_issued_at:             Optional[float] = None
    token_presented_at:          Optional[float] = None
    token_validation_at:         Optional[float] = None
    token_validity_duration_s:   Optional[float] = None
    challenge_issued_at:         Optional[float] = None
    challenge_response_at:       Optional[float] = None
    protected_session_started_at: Optional[float] = None
    protected_session_ended_at:   Optional[float] = None
    renewal_requested_at:        Optional[float] = None
    renewed_token_issued_at:      Optional[float] = None
    generation_profile:           str = "historical-27135bf"
    attack_scenario_intent:       bool = False
    observable_anomaly:           bool = False
    observable_violation_candidate: bool = False
    injection_records:            Tuple[dict, ...] = field(default_factory=tuple)

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
        persistent_context: Optional[PersistentDeviceContext] = None,
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
        # Wall time may anchor the coordinate for readable exports, but the
        # generated semantic path consults only its SemanticClock thereafter.
        self.start_time       = float(start_time) if start_time is not None else time.time()
        self.persistent_context = persistent_context or PersistentDeviceContext(
            device_id=device_id
        )
        if self.persistent_context.device_id != device_id:
            raise ValueError("persistent context device_id must match EventEngine device_id")
        self.last_authentication_context: Optional[AuthenticationSessionContext] = None

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
        initial_state, normal_steps, injection_position = self._execution_plan(spec)
        trace_start = self.persistent_context.begin_trace(self.start_time)
        semantic_clock = SemanticClock(trace_start)
        sm         = StateMachine(initial_state=initial_state)
        events:    List[AuthEvent] = []
        # ``session_id`` is the historical per-trace grouping id.  Keep it for
        # compatibility while assigning distinct semantic identifiers below.
        legacy_session_id = str(uuid.uuid4())
        trace_id          = str(uuid.uuid4())
        is_attack  = spec.is_anomaly
        synchronized_profile = (
            spec.generation_profile == SYNCHRONIZED_GENERATION_PROFILE
        )
        profile    = DELAY_PROFILE   # single, label-independent timing for every session

        # ── Session-level MQTT / token context (one value per session) ─────────
        token_scope:  str = random.choice(TOKEN_SCOPES)
        scope_resource, scope_permission = token_scope.split(":", 1)
        requested_action = "write" if scope_permission == "readwrite" else scope_permission
        topic:        str = f"iot/{self.device_id[:8]}/{scope_resource}"
        resource_id:  str = f"resource://{self.device_id[:8]}/{scope_resource}"

        # Phase 3 — temporal tracker for this session
        # The pre-C1 EventEngine already exposed cfg.security.token_lifetime_s
        # as token_expiry. Use that same historical reference-profile value for
        # enforcement; legacy TemporalEngine 3600/120-second defaults are not
        # promoted into synchronized semantic truth.
        te = TemporalEngine(
            config=TemporalConfig(
                token_lifetime=cfg.security.token_lifetime_s,
                attack_token_life=cfg.security.token_lifetime_s,
                replay_window=cfg.security.replay_window_s,
            ),
            is_attack=False,
        )

        # ── Mutable run-state threaded through every step (see _run_step) ──────
        security_context = AuthenticationSessionContext(
            device_id=self.device_id,
            trace_id=trace_id,
            scenario_id=spec.scenario_id,
            legacy_session_id=legacy_session_id,
            current_auth_state=initial_state,
            current_timestamp=semantic_clock.now,
            token_scope=token_scope,
            topic=topic,
            resource_id=resource_id,
            requested_action=requested_action,
            semantic_time_domain=SEMANTIC_TIME_DOMAIN,
            trace_started_at=semantic_clock.now,
        )
        rs: Dict = {
            "current_ts":   semantic_clock.now,
            "semantic_clock": semantic_clock,
            "token_id":     None,          # set once a token is issued
            "token_expiry": None,
            "nonce":        None,
            "retry_count":  0,
            "session_id":   legacy_session_id,
            "topic":        topic,
            "resource_id":  resource_id,
            "token_scope":  token_scope,
            "security_context": security_context,
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
            # Detection realism: True for an evasive (stealth) attack session.
            # Read by _build_context to also suppress rate-based traffic; never
            # exported as a feature.
            "_stealth":                   False,
        }

        # ── Stealth decision (attacks only) ───────────────────────────────────
        # Scenario intent is retained independently from observable evidence.
        # A stealth selection executes a coherent trace with no transformation
        # and therefore cannot become observable anomaly truth.
        stealth = (spec.is_anomaly
                   and random.random() < STEALTH_FRACTION.get(spec.anomaly_type, DEFAULT_STEALTH))
        ctx["_stealth"] = stealth

        # ── Run legitimate steps ──────────────────────────────────────────────
        # Detected attacks run up to the injection point (then inject below);
        # normal sessions and stealth attacks run the full flow.
        if (
            synchronized_profile
            and spec.is_anomaly
            and not stealth
            and spec.anomaly_type == "timestamp_inconsistency"
        ):
            steps_to_run = normal_steps
        else:
            steps_to_run = (
                normal_steps[:injection_position]
                if (spec.is_anomaly and not stealth) else normal_steps
            )

        for event_type in steps_to_run:
            self._run_step(event_type, sm, rs, ctx, te, events, profile, spec)

        # ── Synchronized controlled transformations ──────────────────────────
        if synchronized_profile and spec.is_anomaly and not stealth:
            record = self._apply_synchronized_injection(
                spec=spec,
                normal_steps=normal_steps,
                injection_position=injection_position,
                sm=sm,
                rs=rs,
                ctx=ctx,
                te=te,
                events=events,
                profile=profile,
            )
            security_context.injection_records.append(record)

        # ── Historical injection path retained as pre-canonical evidence ─────
        elif spec.is_anomaly and not stealth:
            delay          = self._sample_delay(spec.injection_event, profile)
            rs["current_ts"] = semantic_clock.advance(delay)
            security_context.current_timestamp = semantic_clock.now
            # The semantic timestamp stays on the monotonic clock. A historical
            # timestamp_inconsistency injection alters only separately exposed
            # observed/declared evidence in preparation for C1.5 reconciliation.
            semantic_event_ts = rs["current_ts"]
            observed_timestamp = semantic_event_ts
            observed_timestamp_source = "semantic_clock"
            targeted_temporal_relationship = None

            # ── Per-variant detector-signal enrichment ────────────────────────
            # replay_token: token presented well outside the replay window
            if spec.anomaly_type == "replay_token":
                stolen_age = random.uniform(120, 600)
                te.record_token_issued(rs["current_ts"] - stolen_age)
                te.record_token_presented(rs["current_ts"])
                ctx["replay_window_violation"] = 1
                ctx["token_age_at_replay"]     = round(stolen_age, 2)
                ctx["credential_status"]       = 0

            # nonce_reuse: reuse the existing nonce value so n_nonce_reuses > 0.
            # The same value appears on both the original NONCE_RECEIVED event
            # and this injected event, making output_views count it as a reuse.
            if spec.anomaly_type == "nonce_reuse" and rs["nonce"] is not None:
                ctx["nonce_age_at_reuse"] = round(te.nonce_age(rs["current_ts"]), 2)

            # timestamp_inconsistency: device declares a past time on this event
            if spec.anomaly_type == "timestamp_inconsistency":
                delta            = random.uniform(400, 900)
                observed_timestamp = semantic_event_ts - delta
                observed_timestamp_source = "injected_device_timestamp"
                targeted_temporal_relationship = "declared_event_time_after_predecessor"
                ctx["timestamp_delta_s"] = round(delta, 2)

            # duplicate_sequence: full auth sequence replayed inside open session
            if spec.anomaly_type == "duplicate_sequence":
                ctx["duplicate_session_count"] = 1

            # State the legitimate flow had reached before the injection — the
            # continuation (below) resumes from here so the session can complete.
            pre_injection_state = sm.state
            sm.force(spec.injection_from_state)
            try:
                sm.advance(spec.injection_event)
                new_state = sm.state
            except TransitionError:
                new_state = spec.injection_from_state
            security_context.current_auth_state = new_state

            identity_claim = None

            # ── Phase 5: identity / session anomaly enrichment ────────────────
            if spec.anomaly_type == "impersonation":
                identity_claim                 = f"victim-{str(uuid.uuid4())[:8]}"
                ctx["source_ip_change"]        = 1
                ctx["credential_status"]       = 0
                ctx["identity_claim"]          = identity_claim
                ctx["identity_claim_mismatch"] = 1   # claimed_id != device_id

            elif spec.anomaly_type == "identity_token_mismatch":
                # Attacker presents a token issued for a *different* device.
                rs["token_id"]                 = f"foreign-{str(uuid.uuid4())}"
                identity_claim                 = f"victim-{str(uuid.uuid4())[:8]}"
                ctx["identity_claim"]          = identity_claim
                ctx["credential_status"]       = 0
                ctx["token_device_mismatch"]   = 1
                ctx["identity_claim_mismatch"] = 1

            elif spec.anomaly_type == "access_without_auth":
                ctx["credential_status"]           = 0  # no auth = no valid credential
                ctx["unauthorized_access_attempt"] = 1
                ctx["steps_before_access"]         = spec.injection_position

            # Carry the original nonce so output_views detects the duplicate.
            injected_nonce = (
                rs["nonce"]
                if spec.anomaly_type == "nonce_reuse"
                else (rs["nonce"] if spec.injection_event in NONCE_CARRYING_EVENTS else None)
            )
            inj_token_id = rs["token_id"] if spec.injection_event in TOKEN_CARRYING_EVENTS else None

            if spec.injection_event == EventType.ACCESS_REQUEST:
                security_context.start_access_request()

            ev = self._make_event(
                event_type=spec.injection_event, prev_state=spec.injection_from_state,
                new_state=new_state, result=EventResult.FAILURE,
                failure_reason=f"invalid_transition_{spec.anomaly_type}",
                session_id=legacy_session_id, scenario_id=spec.scenario_id,
                security_context=security_context,
                timestamp=semantic_event_ts,
                observed_timestamp=observed_timestamp,
                observed_timestamp_source=observed_timestamp_source,
                targeted_temporal_relationship=targeted_temporal_relationship,
                delay=delay, retry_count=rs["retry_count"],
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
            security_context.record_result(
                EventResult.FAILURE,
                f"invalid_transition_{spec.anomaly_type}",
            )

            # ── Continuation: resume the legitimate flow for a fraction of the
            # in-session replay/renewal anomalies so they still reach SESSION_OPENED
            # / ACCESS_GRANTED / SESSION_CLOSED and overlap normal sessions. ──────
            resume = random.random() < CONTINUE_AFTER_INJECTION.get(spec.anomaly_type, 0.0)
            if injection_position < len(normal_steps) and resume:
                sm.force(pre_injection_state)
                security_context.current_auth_state = pre_injection_state
                for event_type in normal_steps[injection_position:]:
                    self._run_step(event_type, sm, rs, ctx, te, events, profile, spec)

        # ── False positives: a fraction of benign sessions exhibit a suspicious-
        # looking but legitimate condition with no attack present → keeps
        # precision realistic (< 1). A minority trip an actual detector flag
        # (clock-skew replay), the real-world source of IDS false alarms. ───────
        elif not spec.is_anomaly and random.random() < FALSE_POSITIVE_FRACTION:
            roll = random.random()
            if roll < 0.35:
                ctx["source_ip_change"] = 1                       # device roamed networks
            elif roll < 0.65:
                ctx["failed_auth_count"] += random.randint(1, 2)  # flaky link retries
            else:
                # Legitimate token presented just outside a tight replay window
                # because of clock skew — trips the replay detector, no attack.
                ctx["replay_window_violation"] = 1
                ctx["token_age_at_replay"]     = round(random.uniform(62, 95), 2)

        # ── Final auth_result reflects the accumulated state (post-continuation) ─
        ctx["auth_result"] = ctx["final_auth_result"]

        # ── Build SessionContext ───────────────────────────────────────────────
        context = self._build_context(
            spec, events, ctx, te, security_context, self.persistent_context
        )
        security_context.trace_ended_at = semantic_clock.now
        self.persistent_context.complete_trace(semantic_clock.now)
        # Rebuild after closing the trace so exported context contains the final
        # authoritative cursor. Feature sampling consumes no semantic time.
        context.trace_ended_at = semantic_clock.now
        self.last_authentication_context = security_context
        return events, context

    def _apply_synchronized_injection(
        self,
        *,
        spec: ScenarioSpec,
        normal_steps: List[EventType],
        injection_position: Optional[int],
        sm: StateMachine,
        rs: Dict,
        ctx: Dict,
        te: TemporalEngine,
        events: List[AuthEvent],
        profile: Dict[EventType, Tuple[float, float]],
    ) -> InjectionRecord:
        """Apply one supported C1.5 transformation and retain its evidence."""
        if spec.anomaly_type not in VARIANT_CAPABILITIES:
            raise ValueError(f"unknown synchronized anomaly variant: {spec.anomaly_type}")
        capability = VARIANT_CAPABILITIES[spec.anomaly_type]
        if capability.status is not VariantCapabilityStatus.SUPPORTED_PENDING_VALIDATION:
            raise ValueError(
                f"quarantined variant cannot execute in synchronized profile: "
                f"{spec.anomaly_type}"
            )

        security_context: AuthenticationSessionContext = rs["security_context"]
        injection_id = str(uuid.uuid4())

        if spec.anomaly_type == "nonce_reuse":
            source = next(
                (
                    event for event in events
                    if event.event_type == EventType.NONCE_RECEIVED
                    and event.nonce
                    and event.auth_attempt_id != security_context.current_auth_attempt_id
                ),
                None,
            )
            original_nonce = rs.get("nonce")
            if source is None or injection_position is None:
                return InjectionRecord(
                    injection_id=injection_id,
                    historical_scenario_name=spec.anomaly_type,
                    anomaly_variant_name=spec.anomaly_type,
                    capability_status=capability.status.value,
                    mapped_semantic_concept=capability.semantic_concept,
                    invariant_families=capability.invariant_families,
                    trace_id=security_context.trace_id,
                    device_id=self.device_id,
                    session_id=security_context.legacy_session_id,
                    auth_attempt_id=security_context.current_auth_attempt_id,
                    declared_history_scope=capability.history_scope,
                    intended_observable_violation="reuse challenge nonce across authentication attempts",
                    validation_status="injection_not_applied_missing_source_evidence",
                )

            rs["nonce"] = source.nonce
            security_context.current_challenge_nonce = source.nonce
            self._run_step(
                EventType.NONCE_RECEIVED,
                sm,
                rs,
                ctx,
                te,
                events,
                profile,
                spec,
                controlled_success=True,
            )
            reused = events[-1]
            evidence_ok = (
                reused.nonce == source.nonce
                and reused.auth_attempt_id != source.auth_attempt_id
            )
            reused.injection_id = injection_id
            reused.anomaly_variant_name = spec.anomaly_type
            reused.invariant_families = capability.invariant_families
            reused.anomaly_label = spec.anomaly_type if evidence_ok else None
            reused.source_context = "controlled_injection" if evidence_ok else "normal"
            ctx["nonce_age_at_reuse"] = round(
                max(0.0, reused.timestamp - source.timestamp), 6
            )

            for event_type in normal_steps[injection_position + 1:]:
                self._run_step(event_type, sm, rs, ctx, te, events, profile, spec)

            return InjectionRecord(
                injection_id=injection_id,
                historical_scenario_name=spec.anomaly_type,
                anomaly_variant_name=spec.anomaly_type,
                capability_status=capability.status.value,
                mapped_semantic_concept=capability.semantic_concept,
                invariant_families=capability.invariant_families,
                targeted_event_type=EventType.NONCE_RECEIVED.value,
                targeted_action_or_context="renewal authentication attempt challenge response",
                source_evidence_event_ids=(source.event_id,),
                source_material_identifier=source.nonce,
                source_trace_id=source.trace_id,
                source_session_id=source.session_id,
                source_auth_attempt_id=source.auth_attempt_id,
                original_value=original_nonce,
                injected_value=source.nonce,
                injection_parameters={"transformation": "replace_nonce_with_prior_attempt_nonce"},
                trace_id=reused.trace_id,
                device_id=reused.device_id,
                session_id=reused.session_id,
                auth_attempt_id=reused.auth_attempt_id,
                declared_history_scope=capability.history_scope,
                intended_observable_violation="same nonce material reused across authentication attempts",
                transformation_applied=True,
                evidence_check_passed=evidence_ok,
                observable_violation_candidate=evidence_ok,
            )

        target = next(
            (event for event in events if event.event_type == EventType.RESPONSE_SENT),
            None,
        )
        if target is None:
            return InjectionRecord(
                injection_id=injection_id,
                historical_scenario_name=spec.anomaly_type,
                anomaly_variant_name=spec.anomaly_type,
                capability_status=capability.status.value,
                mapped_semantic_concept=capability.semantic_concept,
                invariant_families=capability.invariant_families,
                trace_id=security_context.trace_id,
                device_id=self.device_id,
                session_id=security_context.legacy_session_id,
                declared_history_scope=capability.history_scope,
                intended_observable_violation="observed response precedes causal predecessor",
                validation_status="injection_not_applied_missing_target_evidence",
            )

        target_index = events.index(target)
        predecessor = events[target_index - 1] if target_index else None
        original_observed = target.observed_timestamp
        offset_s = random.uniform(400, 900)
        predecessor_observed = (
            predecessor.observed_timestamp
            if predecessor and predecessor.observed_timestamp is not None
            else predecessor.timestamp if predecessor else target.timestamp
        )
        injected_observed = original_observed - offset_s
        target.observed_timestamp = injected_observed
        target.observed_timestamp_source = "injected_device_timestamp"
        target.targeted_temporal_relationship = "declared_event_time_after_predecessor"
        target.injection_id = injection_id
        target.anomaly_variant_name = spec.anomaly_type
        target.invariant_families = capability.invariant_families
        evidence_ok = (
            predecessor is not None
            and target.timestamp > predecessor.timestamp
            and injected_observed < predecessor_observed
        )
        target.anomaly_label = spec.anomaly_type if evidence_ok else None
        target.source_context = "controlled_injection" if evidence_ok else "normal"
        ctx["timestamp_delta_s"] = round(offset_s, 6)

        return InjectionRecord(
            injection_id=injection_id,
            historical_scenario_name=spec.anomaly_type,
            anomaly_variant_name=spec.anomaly_type,
            capability_status=capability.status.value,
            mapped_semantic_concept=capability.semantic_concept,
            invariant_families=capability.invariant_families,
            targeted_event_type=target.event_type.value,
            targeted_action_or_context="observed timestamp of causal response event",
            source_evidence_event_ids=(predecessor.event_id,) if predecessor else (),
            source_trace_id=predecessor.trace_id if predecessor else None,
            source_session_id=predecessor.session_id if predecessor else None,
            source_auth_attempt_id=(
                predecessor.auth_attempt_id if predecessor else None
            ),
            original_value=original_observed,
            injected_value=injected_observed,
            injection_parameters={"offset_s": round(offset_s, 6)},
            trace_id=target.trace_id,
            device_id=target.device_id,
            session_id=target.session_id,
            auth_attempt_id=target.auth_attempt_id,
            declared_history_scope=capability.history_scope,
            intended_observable_violation="observed response timestamp precedes predecessor",
            transformation_applied=True,
            evidence_check_passed=evidence_ok,
            observable_violation_candidate=evidence_ok,
        )

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
        controlled_success: bool = False,
    ) -> None:
        """
        Execute one legitimate flow step: advance the state machine, update the
        shared token/nonce/latency context (rs / ctx), and append the AuthEvent.

        Used for both the pre-injection steps and the optional post-injection
        continuation, so every completed session — normal or anomalous — goes
        through exactly the same event-construction path.
        """
        security_context: AuthenticationSessionContext = rs["security_context"]
        semantic_clock: SemanticClock = rs["semantic_clock"]
        prev_state = sm.state

        # Establish identifier scope before emitting the event that starts it.
        if event_type == EventType.AUTHENTICATION_REQUEST:
            security_context.start_auth_attempt()
        elif event_type == EventType.RENEWAL_REQUEST:
            security_context.start_auth_attempt(renewal=True)
        elif event_type == EventType.RETRY and prev_state in {
            AuthState.AUTH_FAILED,
            AuthState.TOKEN_EXPIRED,
        }:
            security_context.start_auth_attempt()
        elif event_type == EventType.ACCESS_REQUEST or (
            event_type == EventType.RETRY and prev_state == AuthState.ACCESS_DENIED
        ):
            security_context.start_access_request()

        # Phase 3: use retry backoff delay for RETRY events
        if event_type == EventType.RETRY:
            delay = te.next_retry_delay()
        else:
            delay = self._sample_delay(event_type, profile)
        rs["current_ts"] = semantic_clock.advance(delay)
        security_context.current_timestamp = rs["current_ts"]
        result, failure_reason = self._outcome(event_type, is_anomaly=False)
        if (
            spec.generation_profile == SYNCHRONIZED_GENERATION_PROFILE
            and event_type in SYNCHRONIZED_RELIABLE_PREREQUISITES
        ):
            result, failure_reason = EventResult.SUCCESS, None
        if controlled_success:
            result, failure_reason = EventResult.SUCCESS, None

        # Success-dependent operations require evidence in the explicit
        # security context, not merely a reachable legacy FSM state.
        if event_type == EventType.TOKEN_ISSUED and (
            security_context.authentication_result is not AuthenticationResult.SUCCESS
            or security_context.current_auth_attempt_result
            is not AuthenticationResult.SUCCESS
        ):
            result, failure_reason = EventResult.FAILURE, "authentication_not_established"
        elif event_type == EventType.TOKEN_PRESENTED and not security_context.token_issued:
            result, failure_reason = EventResult.FAILURE, "token_not_issued"
        elif event_type == EventType.TOKEN_VALIDATED and not security_context.token_presented:
            result, failure_reason = EventResult.FAILURE, "token_not_presented"
        elif event_type == EventType.TOKEN_VALIDATED and te.is_token_expired(
            semantic_clock.now
        ):
            result, failure_reason = EventResult.FAILURE, "token_expired"
        elif event_type == EventType.SESSION_OPENED and (
            not security_context.authenticated_context_active
            or security_context.token_validation_result is not TokenValidationResult.VALIDATED
            or not security_context.token_context_active
        ):
            result, failure_reason = EventResult.FAILURE, "session_security_context_incomplete"

        authorization_evaluation = None
        if event_type == EventType.ACCESS_GRANTED:
            request = security_context.current_access_request
            if request is None:
                result, failure_reason = EventResult.FAILURE, "missing_access_request"
            else:
                authorization_evaluation = ReferenceAuthorizationPolicy.evaluate(
                    security_context, request
                )
                if authorization_evaluation[0] is not AuthorizationDecision.GRANTED:
                    result = EventResult.FAILURE
                    failure_reason = authorization_evaluation[1]

        transition_applied = False
        if result == EventResult.FAILURE and event_type not in NEGATIVE_OUTCOME_TRANSITIONS:
            new_state = prev_state
        else:
            try:
                new_state = sm.advance(event_type)
                transition_applied = True
            except TransitionError:
                new_state      = prev_state
                result         = EventResult.FAILURE
                failure_reason = "unexpected_transition_error"
        security_context.current_auth_state = new_state
        operation_succeeded = transition_applied and result == EventResult.SUCCESS

        # ── Update shared token/nonce context ─────────────────────────────────
        if event_type == EventType.TOKEN_ISSUED and operation_succeeded:
            refreshing_existing_token = security_context.token_issued
            rs["token_id"]     = str(uuid.uuid4())
            rs["token_expiry"] = rs["current_ts"] + cfg.security.token_lifetime_s
            security_context.token_id = rs["token_id"]
            security_context.token_issued_at = semantic_clock.now
            security_context.token_validity_duration_s = cfg.security.token_lifetime_s
            security_context.token_expiry = rs["token_expiry"]
            if refreshing_existing_token:
                te.record_renewal(semantic_clock.now)
                security_context.renewed_token_issued_at = semantic_clock.now
            else:
                te.record_token_issued(semantic_clock.now)
            security_context.token_issued = True
            security_context.token_presented = False
            security_context.token_presented_at = None
            security_context.token_validation_at = None
            security_context.token_validation_result = TokenValidationResult.NOT_EVALUATED
            security_context.token_context_active = False
        if event_type == EventType.RENEWAL_REQUEST and operation_succeeded:
            # A request does not refresh validity before credentials are issued.
            security_context.renewal_requested_at = semantic_clock.now
        if event_type == EventType.TOKEN_PRESENTED and operation_succeeded:
            security_context.token_presented = True
            security_context.token_presented_at = semantic_clock.now
            te.record_token_presented(semantic_clock.now)
        if event_type == EventType.TOKEN_VALIDATED:
            security_context.token_validation_result = (
                TokenValidationResult.VALIDATED
                if operation_succeeded else TokenValidationResult.REJECTED
            )
            security_context.token_context_active = operation_succeeded
            security_context.token_validation_at = semantic_clock.now
        elif event_type == EventType.TOKEN_REJECTED and transition_applied:
            security_context.token_validation_result = TokenValidationResult.REJECTED
            security_context.token_presented = False
            security_context.token_context_active = False
        if event_type == EventType.CHALLENGE_SENT and operation_succeeded:
            rs["nonce"] = hashlib.blake2s(uuid.uuid4().bytes).hexdigest()[:16]
            security_context.current_challenge_nonce = rs["nonce"]
            security_context.challenge_issued_at = semantic_clock.now
            security_context.challenge_response_at = None
            te.record_nonce_issued(semantic_clock.now)
        elif event_type == EventType.RESPONSE_SENT and operation_succeeded:
            security_context.challenge_response_at = semantic_clock.now
        if event_type in {
            EventType.AUTHENTICATION_FAILURE,
            EventType.TOKEN_REJECTED,
        } and transition_applied:
            rs["retry_count"]        += 1
            security_context.retry_count = rs["retry_count"]
            ctx["failed_auth_count"] += 1
            te.record_failure()                              # Phase 3
        if event_type == EventType.RETRY:
            ctx["n_retries_fired"] += 1

        if event_type == EventType.AUTHENTICATION_SUCCESS:
            if operation_succeeded:
                security_context.authentication_result = AuthenticationResult.SUCCESS
                security_context.authenticated_identity = self.device_id
                security_context.authenticated_context_active = True
            else:
                security_context.record_authentication_failure()
        elif event_type == EventType.AUTHENTICATION_FAILURE and transition_applied:
            security_context.record_authentication_failure()
        elif event_type in AUTHENTICATION_INTERACTION_EVENTS and result == EventResult.FAILURE:
            security_context.record_authentication_failure()

        if event_type == EventType.SESSION_OPENED and operation_succeeded:
            security_context.open_protected_session(semantic_clock.now)

        if event_type == EventType.ACCESS_GRANTED:
            if authorization_evaluation is None:
                decision, reason = AuthorizationDecision.DENIED, "authorization_unavailable"
            else:
                decision, reason = authorization_evaluation
            outcome = (
                ResourceOperationOutcome.SUCCESS
                if decision is AuthorizationDecision.GRANTED and operation_succeeded
                else (
                    ResourceOperationOutcome.FAILURE
                    if decision is AuthorizationDecision.GRANTED
                    else ResourceOperationOutcome.NOT_EXECUTED
                )
            )
            security_context.record_access_decision(decision, outcome, reason)
            ctx["authorization_result"] = int(decision is AuthorizationDecision.GRANTED)
        elif event_type == EventType.ACCESS_DENIED and transition_applied:
            security_context.record_access_decision(
                AuthorizationDecision.DENIED,
                ResourceOperationOutcome.DENIED,
                "reference_policy_denial",
            )
            ctx["authorization_result"] = 0

        if event_type in {
            EventType.SESSION_CLOSED,
            EventType.DISCONNECT,
            EventType.TIMEOUT,
        } and transition_applied:
            security_context.terminate_session(semantic_clock.now)

        # ── Phase C: drive the real domain entities (flag-gated; no-op if None) ─
        # Exercises ECDH / enrollment / token issuance / broker sessions on the
        # core/ objects. Only override is the real token id at issuance; all
        # leakage-tuned feature values are left untouched.
        if self.driver is not None and operation_succeeded:
            overrides = self.driver.on_event(event_type, rs, rs["current_ts"])
            if overrides:
                rs.update(overrides)
                if "token_id" in overrides:
                    security_context.token_id = overrides["token_id"]

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
        elif event_type == EventType.AUTHENTICATION_SUCCESS and operation_succeeded:
            ctx["s3_latency_ms"]      = round(delay_ms, 2)
            ctx["auth_latency_ms"]    = round(delay_ms, 2)
            ctx["final_auth_result"]  = 1
            ctx["connack_code"]       = "success"
            ctx["credential_status"]  = 1
        elif event_type == EventType.AUTHENTICATION_FAILURE and transition_applied:
            # Only update s3 if we haven't succeeded yet
            if ctx["final_auth_result"] == 0:
                ctx["s3_latency_ms"]   = round(delay_ms, 2)
                ctx["auth_latency_ms"] = round(delay_ms, 2)
            ctx["connack_code"] = failure_reason or "auth_failure"
        elif (event_type == EventType.TOKEN_ISSUED and operation_succeeded
              and ctx["s4_latency_ms"] == 0.0):
            ctx["s4_latency_ms"] = round(delay_ms, 2)
        elif event_type == EventType.SESSION_OPENED and operation_succeeded:
            ctx["s5_latency_ms"]        = round(delay_ms, 2)
            ctx["session_present"]      = 1
        elif event_type == EventType.RENEWAL_REQUEST and operation_succeeded:
            ctx["s6_latency_ms"]    = round(delay_ms, 2)
            ctx["re_auth_required"] = 1
        elif event_type == EventType.ACCESS_DENIED and transition_applied:
            ctx["topic_scope_violation"] = 1 if random.random() < 0.3 else 0

        ev_token_id = rs["token_id"] if event_type in TOKEN_CARRYING_EVENTS else None
        ev = self._make_event(
            event_type=event_type, prev_state=prev_state,
            new_state=new_state, result=result,
            failure_reason=failure_reason, session_id=rs["session_id"],
            scenario_id=spec.scenario_id, timestamp=rs["current_ts"],
            security_context=security_context,
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

        security_context.record_result(result, failure_reason)
        if event_type == EventType.AUTHENTICATION_SUCCESS and operation_succeeded:
            security_context.record_authentication_success(ev.event_id)
        if event_type in {
            EventType.TOKEN_VALIDATED,
            EventType.TOKEN_REJECTED,
        }:
            security_context.token_validation_event_id = ev.event_id
        if result == EventResult.SUCCESS:
            self.persistent_context.record_successful_event(event_type, new_state)

        if event_type in {
            EventType.AUTHENTICATION_SUCCESS,
            EventType.AUTHENTICATION_FAILURE,
        }:
            security_context.finish_auth_attempt()

    # ══════════════════════════════════════════════════════════════════════════
    # SessionContext builder
    # ══════════════════════════════════════════════════════════════════════════

    def _build_context(
        self,
        spec:   ScenarioSpec,
        events: List[AuthEvent],
        ctx:    Dict,
        te:     Optional["TemporalEngine"] = None,
        security_context: Optional[AuthenticationSessionContext] = None,
        persistent_context: Optional[PersistentDeviceContext] = None,
    ) -> SessionContext:
        is_attack   = spec.is_anomaly
        # Phase 3 fix: use the actual anomaly label, not a generic "attack" string
        attack_type = spec.anomaly_type if is_attack else "normal"

        # Traffic intensity depends on the attack TYPE, not the label: only
        # genuinely rate-based attacks flood; protocol-logic attacks share the
        # normal rate band (see _sample_traffic_rate / RATE_BASED_ATTACKS). A
        # stealth (evasive) attack keeps the normal rate band too — flooding
        # would give it away.
        is_rate_based        = (is_attack and attack_type in RATE_BASED_ATTACKS
                                and not ctx.get("_stealth", False))
        pkt_rate, msg_rate   = _sample_traffic_rate(is_rate_based)

        # ── Network features ──────────────────────────────────────────────────
        # tcp_rtt is a property of the network path, not of the attacker's intent,
        # so it is drawn from one shared distribution for both classes. (Keying it
        # on is_attack previously made it a mild leak.)
        tcp_rtt = max(1.0, random.gauss(20.0, 8.0))

        inter_arrival = round(1000.0 / pkt_rate, 2)
        frame_len     = random.randint(64, 256)
        seg_len       = random.randint(128, 512)
        # Session span comes exclusively from authoritative semantic timestamps.
        session_span  = max(0.0, max(e.timestamp for e in events) - events[0].timestamp)
        conn_duration = round(session_span * 1000, 2)

        # ── MQTT features ─────────────────────────────────────────────────────
        qos_level    = random.choice([0, 1, 2])
        topic        = (
            security_context.topic
            if security_context else f"iot/{self.device_id[:8]}/telemetry"
        )
        # Payload size is drawn from one shared distribution regardless of the
        # label. Keying it on is_attack (10-512 vs 512-8192) made byte_rate
        # (= message_rate * payload_size) a perfect discriminator (AUC 0.96).
        # Genuinely high-volume attacks still stand out through their elevated
        # message_rate (see RATE_BASED_ATTACKS / _sample_traffic_rate); a replay
        # or impersonation has no reason to carry a 16x larger payload.
        payload_size = random.randint(10, 512)
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

        session_dur = session_span

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
        attack_phase = spec.injection_event.value if is_attack else "none"
        severity     = SEVERITY_MAP.get(spec.anomaly_type, "none") if is_attack else "none"

        access_requests = (
            [security_context.access_requests[request_id]
             for request_id in security_context.access_request_ids]
            if security_context else []
        )
        latest_access = access_requests[-1] if access_requests else None
        injection_records = (
            tuple(record.to_dict() for record in security_context.injection_records)
            if security_context else ()
        )
        observable_candidate = any(
            record.get("observable_violation_candidate", False)
            for record in injection_records
        )
        if spec.generation_profile != SYNCHRONIZED_GENERATION_PROFILE:
            # Compatibility classification for explicitly requested historical
            # traces. Scenario intent alone still does not label stealth traces.
            observable_candidate = any(event.anomaly_label for event in events)

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
            # C1.2 identifiers / persistence scope
            device_id                   = self.device_id,
            trace_id                    = security_context.trace_id if security_context else "",
            scenario_id                 = spec.scenario_id,
            legacy_session_id           = security_context.legacy_session_id if security_context else "",
            protected_session_id        = security_context.protected_session_id if security_context else None,
            auth_attempt_ids             = tuple(security_context.auth_attempt_ids) if security_context else (),
            renewal_auth_attempt_ids     = tuple(security_context.renewal_auth_attempt_ids) if security_context else (),
            refreshes_protected_session_id = (
                security_context.refreshes_protected_session_id
                if security_context else None
            ),
            persistent_enrolled         = persistent_context.enrolled if persistent_context else False,
            persistent_paired           = persistent_context.paired if persistent_context else False,
            authentication_result_semantic = (
                security_context.authentication_result.value
                if security_context else AuthenticationResult.NOT_EVALUATED.value
            ),
            last_authentication_attempt_result = (
                security_context.current_auth_attempt_result.value
                if security_context else AuthenticationResult.NOT_EVALUATED.value
            ),
            authenticated_identity      = (
                security_context.authenticated_identity if security_context else None
            ),
            authenticated_context_active = (
                security_context.authenticated_context_active if security_context else False
            ),
            token_validation_result     = (
                security_context.token_validation_result.value
                if security_context else TokenValidationResult.NOT_EVALUATED.value
            ),
            token_context_active        = (
                security_context.token_context_active if security_context else False
            ),
            protected_session_active    = (
                security_context.protected_session_active if security_context else False
            ),
            requested_action            = (
                security_context.requested_action if security_context else None
            ),
            authorization_decision      = (
                latest_access.authorization_decision.value
                if latest_access else AuthorizationDecision.NOT_EVALUATED.value
            ),
            resource_operation_outcome  = (
                latest_access.resource_operation_outcome.value
                if latest_access else ResourceOperationOutcome.NOT_EXECUTED.value
            ),
            access_request_ids          = tuple(
                request.request_id for request in access_requests
            ),
            authorization_decisions     = tuple(
                request.authorization_decision.value for request in access_requests
            ),
            resource_operation_outcomes = tuple(
                request.resource_operation_outcome.value for request in access_requests
            ),
            semantic_time_domain         = (
                security_context.semantic_time_domain
                if security_context else SEMANTIC_TIME_DOMAIN
            ),
            trace_started_at             = (
                security_context.trace_started_at if security_context else None
            ),
            trace_ended_at               = (
                security_context.trace_ended_at if security_context else None
            ),
            token_issued_at              = (
                security_context.token_issued_at if security_context else None
            ),
            token_presented_at           = (
                security_context.token_presented_at if security_context else None
            ),
            token_validation_at          = (
                security_context.token_validation_at if security_context else None
            ),
            token_validity_duration_s    = (
                security_context.token_validity_duration_s if security_context else None
            ),
            challenge_issued_at          = (
                security_context.challenge_issued_at if security_context else None
            ),
            challenge_response_at        = (
                security_context.challenge_response_at if security_context else None
            ),
            protected_session_started_at = (
                security_context.protected_session_started_at
                if security_context else None
            ),
            protected_session_ended_at   = (
                security_context.protected_session_ended_at
                if security_context else None
            ),
            renewal_requested_at         = (
                security_context.renewal_requested_at if security_context else None
            ),
            renewed_token_issued_at      = (
                security_context.renewed_token_issued_at if security_context else None
            ),
            generation_profile           = spec.generation_profile,
            attack_scenario_intent       = spec.is_anomaly,
            observable_anomaly           = observable_candidate,
            observable_violation_candidate = observable_candidate,
            injection_records            = injection_records,
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _execution_plan(
        self,
        spec: ScenarioSpec,
    ) -> Tuple[AuthState, List[EventType], Optional[int]]:
        """Resume a trace from retained onboarding facts where safely possible.

        Full historical flows all begin with ``REGISTRATION_PHASE``.  Only the
        already-established prefix is omitted.  Very short legacy partial flows
        are preserved if omission would make the trace empty; this compatibility
        case does not reset or overwrite the persistent context.
        """
        steps = list(spec.normal_steps)
        retained_state = self.persistent_context.legacy_auth_state()

        # Revocation/blocking cannot be erased by adapting a historical flow
        # that happens to begin with discovery.
        if self.persistent_context.revoked or self.persistent_context.blocked:
            return retained_state, steps, spec.injection_position

        if self.persistent_context.enrolled:
            skip = len(REGISTRATION_PHASE)
        elif self.persistent_context.paired:
            skip = 4
        elif self.persistent_context.discovered:
            skip = 2
        else:
            skip = 0

        prefix_matches = skip > 0 and steps[:skip] == list(REGISTRATION_PHASE[:skip])
        if prefix_matches and len(steps) > skip:
            steps = steps[skip:]
            injection_position = (
                max(0, spec.injection_position - skip)
                if spec.injection_position is not None else None
            )
            return retained_state, steps, injection_position

        # A caller may supply an authentication-only flow explicitly.
        if steps and steps[0] not in REGISTRATION_PHASE:
            return retained_state, steps, spec.injection_position

        # Historical onboarding-only partial traces remain executable rather
        # than becoming empty; persistent facts still live outside this FSM.
        return AuthState.UNREGISTERED, steps, spec.injection_position

    def _make_event(
        self,
        event_type:     EventType,
        prev_state:     AuthState,
        new_state:      AuthState,
        result:         EventResult,
        failure_reason: Optional[str],
        session_id:     str,
        scenario_id:    str,
        security_context: AuthenticationSessionContext,
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
        observed_timestamp: Optional[float] = None,
        observed_timestamp_source: str = "semantic_clock",
        targeted_temporal_relationship: Optional[str] = None,
    ) -> AuthEvent:
        access_request = (
            security_context.current_access_request
            if event_type in {
                EventType.ACCESS_REQUEST,
                EventType.ACCESS_GRANTED,
                EventType.ACCESS_DENIED,
                EventType.RETRY,
            }
            else None
        )
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
            trace_id                   = security_context.trace_id,
            auth_attempt_id            = security_context.current_auth_attempt_id,
            protected_session_id       = security_context.protected_session_id,
            access_request_id          = access_request.request_id if access_request else None,
            timestamp                  = timestamp,
            observed_timestamp         = (
                timestamp if observed_timestamp is None else observed_timestamp
            ),
            observed_timestamp_source  = observed_timestamp_source,
            targeted_temporal_relationship = targeted_temporal_relationship,
            delay_since_previous_event = delay,
            token_id                   = token_id,
            token_expiry               = token_expiry,
            token_scope                = token_scope,
            nonce                      = nonce,
            retry_count                = retry_count,
            topic                      = topic,
            resource_id                = resource_id,
            requested_action           = access_request.requested_action if access_request else None,
            authenticated_identity     = security_context.authenticated_identity,
            token_validation_result    = security_context.token_validation_result.value,
            authorization_decision     = (
                access_request.authorization_decision.value if access_request else None
            ),
            resource_operation_outcome = (
                access_request.resource_operation_outcome.value if access_request else None
            ),
            authenticated_context_active = security_context.authenticated_context_active,
            token_context_active         = security_context.token_context_active,
            protected_session_active     = security_context.protected_session_active,
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
