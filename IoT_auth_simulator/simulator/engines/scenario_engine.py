"""
simulator/engines/scenario_engine.py
──────────────────────────────────────
Layer 1 of 3 — Scenario Engine

Responsibility: define WHAT to simulate.
The scenario engine produces ScenarioSpec objects — declarative descriptions
of a session's event sequence and any anomaly to inject. It does not generate
events or assign timestamps; that is the event engine's job.

Two scenario families
─────────────────────
  NormalScenario  — the complete happy-path flow, no anomalies.
  AnomalyScenario — same base flow, but with one invalid transition injected
                    at a specific position, labelled with an anomaly type.

ScenarioSpec fields
────────────────────
  scenario_id          — unique identifier carried by every AuthEvent in the sequence
  scenario_type        — "normal" or the anomaly label string
  is_anomaly           — bool shortcut
  anomaly_type         — None for normal, one of the 9 anomaly labels otherwise
  normal_steps         — ordered list of EventTypes for the base (normal) flow
  injection_from_state — StateMachine is forced into this state before injection
  injection_event      — the invalid EventType that triggers the anomaly
  injection_position   — how many normal_steps to execute before injecting

Injection mechanism (used by EventEngine)
──────────────────────────────────────────
  1. EventEngine runs normal_steps[:injection_position] normally.
  2. StateMachine is forced to injection_from_state.
  3. EventEngine calls sm.advance(injection_event) → TransitionError is raised.
  4. EventEngine catches the error and emits an AuthEvent with anomaly_label set.
  5. Remaining normal_steps[injection_position:] are skipped (session ends on anomaly).

Normal flow (six-phase lifecycle)
─────────────────────────────────
  DISCOVERY → GATEWAY_ADVERTISEMENT                         (discovery)
  → PAIRING_REQUEST → PAIRING_RESPONSE                      (pairing / ECDH)
  → ENROLLMENT_REQUEST → ENROLLMENT_CONFIRMED               (enrollment)
  → AUTHENTICATION_REQUEST → CHALLENGE_SENT → NONCE_RECEIVED
  → RESPONSE_SENT → AUTHENTICATION_SUCCESS                  (authentication)
  → TOKEN_ISSUED → TOKEN_PRESENTED → TOKEN_VALIDATED
  → SESSION_OPENED                                          (MQTT session)
  → ACCESS_REQUEST → ACCESS_GRANTED → SESSION_CLOSED
"""

import uuid
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from simulator.event_model import AuthState, EventType
from simulator.state_machine import ANOMALY_TRANSITIONS, all_anomaly_types


# ══════════════════════════════════════════════════════════════════════════════
# Canonical normal flow
# ══════════════════════════════════════════════════════════════════════════════

# Discovery → pairing → enrollment prefix (the "registration" phase, expanded
# into its six-phase-lifecycle constituents).
REGISTRATION_PHASE: List[EventType] = [
    EventType.DISCOVERY,
    EventType.GATEWAY_ADVERTISEMENT,
    EventType.PAIRING_REQUEST,
    EventType.PAIRING_RESPONSE,
    EventType.ENROLLMENT_REQUEST,
    EventType.ENROLLMENT_CONFIRMED,
]

NORMAL_FLOW: List[EventType] = [
    *REGISTRATION_PHASE,                # discovery + pairing + enrollment
    EventType.AUTHENTICATION_REQUEST,
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.AUTHENTICATION_SUCCESS,
    EventType.TOKEN_ISSUED,
    EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED,
    EventType.SESSION_OPENED,
    EventType.ACCESS_REQUEST,
    EventType.ACCESS_GRANTED,
    EventType.SESSION_CLOSED,
]

# Normal flow variant: one auth failure followed by a successful retry.
# AUTH_FAILED → RETRY (backoff) → re-enter challenge-response → success.
NORMAL_FLOW_WITH_RETRY: List[EventType] = [
    *REGISTRATION_PHASE,
    EventType.AUTHENTICATION_REQUEST,
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.AUTHENTICATION_FAILURE,   # first attempt fails
    EventType.RETRY,                    # device waits (backoff) and retries
    EventType.CHALLENGE_SENT,           # new challenge issued
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.AUTHENTICATION_SUCCESS,   # second attempt succeeds
    EventType.TOKEN_ISSUED,
    EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED,
    EventType.SESSION_OPENED,
    EventType.ACCESS_REQUEST,
    EventType.ACCESS_GRANTED,
    EventType.SESSION_CLOSED,
]

# Normal flow variant: token renewal mid-session.
# After first access, the token nears expiry → the device re-authenticates with
# a FRESH PoP challenge (challenge → nonce → response) without tearing down the
# MQTT session, then receives a renewed token.
NORMAL_FLOW_WITH_RENEWAL: List[EventType] = [
    *REGISTRATION_PHASE,
    EventType.AUTHENTICATION_REQUEST,
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.AUTHENTICATION_SUCCESS,
    EventType.TOKEN_ISSUED,
    EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED,
    EventType.SESSION_OPENED,
    EventType.ACCESS_REQUEST,
    EventType.ACCESS_GRANTED,
    EventType.RENEWAL_REQUEST,          # token nearing expiry, device renews
    EventType.CHALLENGE_SENT,           # fresh PoP challenge (session kept open)
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
    EventType.AUTHENTICATION_SUCCESS,
    EventType.TOKEN_ISSUED,             # fresh token issued by auth server
    EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED,
    EventType.SESSION_CLOSED,
]

# Canonical authentication prefix (NORMAL_FLOW up to and including SESSION_OPENED).
# Every full session starts with this; the in-session access activity and the
# ending are what vary. Anomaly injection positions are all within this prefix,
# so a session can carry arbitrary trailing activity without affecting them.
AUTH_PREFIX: List[EventType] = list(NORMAL_FLOW[:15])   # 15 events → SESSION_OPEN

# One benign access cycle (request → granted).
CLEAN_ACCESS_CYCLE: List[EventType] = [
    EventType.ACCESS_REQUEST,
    EventType.ACCESS_GRANTED,
]

# A benign access attempt that is denied (topic scope) then retried and granted.
# Realistic, and its odd length helps populate odd n_events values.
DENIED_ACCESS_CYCLE: List[EventType] = [
    EventType.ACCESS_REQUEST,
    EventType.ACCESS_DENIED,
    EventType.RETRY,
    EventType.ACCESS_GRANTED,
]


def build_session_flow() -> List[EventType]:
    """
    Build one benign full-session flow with randomised length.

    Structure: AUTH_PREFIX → 1..4 access cycles (occasionally a denied-then-
    retried one) → an ending that is usually a clean SESSION_CLOSED, sometimes
    an abrupt DISCONNECT (incomplete closure), and occasionally nothing at all
    (session left open). Varying the cycle count and the ending spreads
    n_events across a broad range of BOTH parities, so completed anomalies
    (which carry one extra injected event) land on values that normal sessions
    also occupy — no length is class-exclusive.
    """
    steps = list(AUTH_PREFIX)
    for _ in range(random.choices([1, 2, 3, 4], weights=[45, 30, 15, 10])[0]):
        if random.random() < 0.18:
            steps += DENIED_ACCESS_CYCLE
        else:
            steps += CLEAN_ACCESS_CYCLE

    r = random.random()
    if r < 0.72:
        steps.append(EventType.SESSION_CLOSED)   # clean close
    elif r < 0.85:
        steps.append(EventType.DISCONNECT)       # abrupt drop → incomplete closure
    # else (~15%): no terminal event — session left open (odd-length tail)
    return steps


def build_partial_flow() -> List[EventType]:
    """
    Build a short benign session that drops out early (flaky device / lost
    link): the first k canonical steps with no clean close. Covers the low
    n_events range that overlaps the (short) truncated anomaly sessions, so
    a short session is no longer implicitly anomalous.
    """
    k = random.randint(3, 12)
    return list(NORMAL_FLOW[:k])

# ── State checkpoints within NORMAL_FLOW ─────────────────────────────────────
# Maps EventType → the AuthState the SM will be in AFTER that event fires.
# Used by the scenario engine to pick a sensible injection_position.
FLOW_STATE_AFTER: Dict[EventType, AuthState] = {
    EventType.DISCOVERY:              AuthState.DISCOVERED,
    EventType.GATEWAY_ADVERTISEMENT:  AuthState.DISCOVERED,
    EventType.PAIRING_REQUEST:        AuthState.PAIRING,
    EventType.PAIRING_RESPONSE:       AuthState.PAIRED,
    EventType.ENROLLMENT_REQUEST:     AuthState.ENROLLING,
    EventType.ENROLLMENT_CONFIRMED:   AuthState.ENROLLED,
    EventType.REGISTRATION_REQUEST:   AuthState.ENROLLED,
    EventType.REGISTRATION_CONFIRMED: AuthState.ENROLLED,
    EventType.AUTHENTICATION_REQUEST: AuthState.AUTH_REQUESTED,
    EventType.CHALLENGE_SENT:         AuthState.CHALLENGE_ISSUED,
    EventType.NONCE_RECEIVED:         AuthState.CHALLENGE_ISSUED,
    EventType.RESPONSE_SENT:          AuthState.RESPONSE_SENT,
    EventType.AUTHENTICATION_SUCCESS: AuthState.AUTHENTICATED,
    EventType.TOKEN_ISSUED:           AuthState.TOKEN_ISSUED,
    EventType.TOKEN_PRESENTED:        AuthState.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED:        AuthState.TOKEN_VALIDATED,
    EventType.SESSION_OPENED:         AuthState.SESSION_OPEN,
    EventType.ACCESS_REQUEST:         AuthState.ACCESS_REQUESTED,
    EventType.ACCESS_GRANTED:         AuthState.ACCESS_GRANTED,
    EventType.SESSION_CLOSED:         AuthState.ENROLLED,
}

# ── How many normal steps to run before injecting each anomaly ────────────────
# The injection_position selects the point in NORMAL_FLOW where the anomaly
# is inserted.  The value is the number of steps executed BEFORE injection.
# Chosen so the StateMachine reaches a state close to injection_from_state.
# Positions are indices into NORMAL_FLOW, whose registration phase now spans the
# first 6 events (discovery → enrollment_confirmed, ending in ENROLLED).
ANOMALY_INJECTION_POSITION: Dict[str, int] = {
    "replay_token":             6,   # after ENROLLMENT_CONFIRMED  (state: ENROLLED)
    "nonce_reuse":             11,   # after AUTHENTICATION_SUCCESS (state: AUTHENTICATED)
    "timestamp_inconsistency":  6,   # after ENROLLMENT_CONFIRMED  (state: ENROLLED)
    "access_without_auth":      6,   # after ENROLLMENT_CONFIRMED  (state: ENROLLED)
    "abnormal_failure_rate":   10,   # after RESPONSE_SENT         (state: RESPONSE_SENT)
    "impersonation":           10,   # after RESPONSE_SENT         (state: RESPONSE_SENT)
    "identity_token_mismatch":  6,   # after ENROLLMENT_CONFIRMED  (state: ENROLLED)
    "abnormal_renewal":        12,   # after TOKEN_PRESENTED       (state: TOKEN_PRESENTED)
    "duplicate_sequence":      14,   # after SESSION_OPENED        (state: SESSION_OPEN)
    "connect_flood":            6,   # after ENROLLMENT_CONFIRMED  (state: ENROLLED)
    "delayed_connect":          6,   # after ENROLLMENT_CONFIRMED  (state: ENROLLED / PAIRED)
}


# ══════════════════════════════════════════════════════════════════════════════
# ScenarioSpec — declarative description of one session
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScenarioSpec:
    """
    Declarative description of one session to be executed by the EventEngine.

    The EventEngine reads this spec and:
      - Runs normal_steps[:injection_position] through the StateMachine.
      - If is_anomaly: forces the SM to injection_from_state, then fires
        injection_event (which raises TransitionError), emits a labelled event.
      - If not is_anomaly: runs all normal_steps to completion.
    """

    scenario_id:   str
    scenario_type: str            # "normal" | anomaly label
    is_anomaly:    bool

    # Normal flow definition
    normal_steps: List[EventType] = field(default_factory=lambda: list(NORMAL_FLOW))

    # Anomaly injection (all None for normal scenarios)
    anomaly_type:          Optional[str]       = field(default=None)
    injection_position:    Optional[int]       = field(default=None)
    injection_from_state:  Optional[AuthState] = field(default=None)
    injection_event:       Optional[EventType] = field(default=None)

    def __repr__(self) -> str:
        if self.is_anomaly:
            return (
                f"ScenarioSpec(id={self.scenario_id[:8]}…, "
                f"type={self.anomaly_type}, "
                f"inject_at={self.injection_position})"
            )
        return f"ScenarioSpec(id={self.scenario_id[:8]}…, type=normal, steps={len(self.normal_steps)})"


# ══════════════════════════════════════════════════════════════════════════════
# ScenarioEngine
# ══════════════════════════════════════════════════════════════════════════════

class ScenarioEngine:
    """
    Produces ScenarioSpec objects for the EventEngine to execute.

    Usage
    ─────
        engine = ScenarioEngine()
        spec   = engine.normal()
        spec   = engine.anomaly("replay_token")
        specs  = engine.batch(n_normal=800, n_attack=200, distribution={...})
    """

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)

    # ── Single scenario factories ──────────────────────────────────────────────

    def normal(self) -> ScenarioSpec:
        """
        Generate one normal (benign) scenario spec.

        Uses build_session_flow() so the happy path has a randomised number of
        access cycles and a varied ending (clean close / abrupt disconnect /
        left open) — giving normal sessions a broad, both-parity n_events
        distribution that overlaps the anomaly sessions.
        """
        return ScenarioSpec(
            scenario_id   = str(uuid.uuid4()),
            scenario_type = "normal",
            is_anomaly    = False,
            normal_steps  = build_session_flow(),
        )

    def normal_with_retry(self) -> ScenarioSpec:
        """
        Normal session that recovers from one authentication failure.

        Produces non-zero values for: failed_auth_count, n_authentication_failure,
        n_retry, auth_latency_ms (second attempt).
        """
        return ScenarioSpec(
            scenario_id   = str(uuid.uuid4()),
            scenario_type = "normal",
            is_anomaly    = False,
            normal_steps  = list(NORMAL_FLOW_WITH_RETRY),
        )

    def normal_with_renewal(self) -> ScenarioSpec:
        """
        Normal session that performs a mid-session token renewal.

        Produces non-zero values for: re_auth_required, n_renewal_request,
        s6_latency_ms, n_token_issued (= 2).
        """
        return ScenarioSpec(
            scenario_id   = str(uuid.uuid4()),
            scenario_type = "normal",
            is_anomaly    = False,
            normal_steps  = list(NORMAL_FLOW_WITH_RENEWAL),
        )

    def normal_partial(self) -> ScenarioSpec:
        """
        Normal session that drops out early (flaky device / lost link) after a
        random number of steps, with no clean close.

        Produces short, incomplete benign sessions whose low n_events overlaps
        the truncated anomaly sessions — so a short session is no longer an
        implicit anomaly marker.
        """
        return ScenarioSpec(
            scenario_id   = str(uuid.uuid4()),
            scenario_type = "normal",
            is_anomaly    = False,
            normal_steps  = build_partial_flow(),
        )

    # ── Phase 4: named replay variant factories ───────────────────────────────

    # ── Phase 5: named identity / session anomaly factories ──────────────────

    def impersonation_variant(self) -> ScenarioSpec:
        """
        Device impersonation: attacker opens a session using a stolen identity.
        Produces identity_claim_mismatch=1, source_ip_change=1, credential_status=0.
        """
        return self.anomaly("impersonation")

    def token_session_mismatch(self) -> ScenarioSpec:
        """
        Token-session mismatch: foreign token (issued for another device) presented.
        Produces token_device_mismatch=1, identity_claim_mismatch=1.
        """
        return self.anomaly("identity_token_mismatch")

    def unauthorized_access_variant(self) -> ScenarioSpec:
        """
        Access without authentication: ACCESS_REQUEST before auth is complete.
        Produces unauthorized_access_attempt=1, steps_before_access=injection_position.
        """
        return self.anomaly("access_without_auth")

    def identity_anomalies_batch(self, n_each: int = 25) -> List[ScenarioSpec]:
        """
        Return n_each instances of each of the 3 identity/session anomaly sub-types,
        shuffled. Convenience method for identity-focused dataset generation.
        """
        specs = (
            [self.impersonation_variant()    for _ in range(n_each)] +
            [self.token_session_mismatch()   for _ in range(n_each)] +
            [self.unauthorized_access_variant() for _ in range(n_each)]
        )
        random.shuffle(specs)
        return specs

    # ── Phase 4: named replay variant factories ───────────────────────────────

    def replay_token(self) -> ScenarioSpec:
        """Old token replayed outside the replay window. Produces token_age_at_replay > 0."""
        return self.anomaly("replay_token")

    def nonce_reuse(self) -> ScenarioSpec:
        """Same nonce re-sent after the challenge window. Produces nonce_age_at_reuse > 0."""
        return self.anomaly("nonce_reuse")

    def timestamp_inconsistency(self) -> ScenarioSpec:
        """Response arrives before the challenge. Produces timestamp_delta_s > 0."""
        return self.anomaly("timestamp_inconsistency")

    def duplicate_sequence(self) -> ScenarioSpec:
        """Full auth sequence replayed inside an open session. Produces duplicate_session_count=1."""
        return self.anomaly("duplicate_sequence")

    def replay_variants_batch(self, n_each: int = 25) -> List[ScenarioSpec]:
        """
        Return n_each instances of each of the 4 replay sub-variants, shuffled.
        Convenience method for replay-focused dataset generation.
        """
        specs = (
            [self.replay_token()           for _ in range(n_each)] +
            [self.nonce_reuse()            for _ in range(n_each)] +
            [self.timestamp_inconsistency() for _ in range(n_each)] +
            [self.duplicate_sequence()     for _ in range(n_each)]
        )
        random.shuffle(specs)
        return specs

    # ── Flooding / protocol-abuse variant factories ───────────────────────────

    def abnormal_failure_variant(self) -> ScenarioSpec:
        """Burst of failed auth attempts from one device (should be rate-limited)."""
        return self.anomaly("abnormal_failure_rate")

    def connect_flood(self) -> ScenarioSpec:
        """High rate of MQTT CONNECT packets with invalid credentials (DoS)."""
        return self.anomaly("connect_flood")

    def delayed_connect(self) -> ScenarioSpec:
        """Half-open CONNECT: TCP handshake completes then stalls, holding resources."""
        return self.anomaly("delayed_connect")

    def flooding_batch(self, n_each: int = 25) -> List[ScenarioSpec]:
        """
        Return n_each instances of each of the 3 flooding / protocol-abuse
        variants, shuffled. Convenience method for DoS-focused generation.
        """
        specs = (
            [self.abnormal_failure_variant() for _ in range(n_each)] +
            [self.connect_flood()            for _ in range(n_each)] +
            [self.delayed_connect()          for _ in range(n_each)]
        )
        random.shuffle(specs)
        return specs

    def anomaly(self, anomaly_type: str) -> ScenarioSpec:
        """
        Generate one anomaly scenario spec.

        Picks a random invalid (from_state, event_type) pair for the given
        anomaly_type from ANOMALY_TRANSITIONS, and sets the injection_position
        to the canonical value from ANOMALY_INJECTION_POSITION.

        Raises ValueError for unknown anomaly types.
        """
        if anomaly_type not in ANOMALY_TRANSITIONS:
            raise ValueError(
                f"Unknown anomaly type: '{anomaly_type}'. "
                f"Valid: {all_anomaly_types()}"
            )

        candidates = ANOMALY_TRANSITIONS[anomaly_type]
        from_state, event = random.choice(candidates)

        position = ANOMALY_INJECTION_POSITION.get(anomaly_type, 2)

        # Base flow uses the same randomised builder as normal sessions. All
        # injection positions fall within AUTH_PREFIX, so the variable trailing
        # activity does not affect where the anomaly is injected — but when the
        # EventEngine continues the flow after injection, the continued session
        # inherits the same varied length distribution as normal sessions.
        return ScenarioSpec(
            scenario_id          = str(uuid.uuid4()),
            scenario_type        = anomaly_type,
            is_anomaly           = True,
            normal_steps         = build_session_flow(),
            anomaly_type         = anomaly_type,
            injection_position   = position,
            injection_from_state = from_state,
            injection_event      = event,
        )

    # ── Batch generation ───────────────────────────────────────────────────────

    def batch(
        self,
        n_normal:      int,
        n_attack:      int,
        distribution:  Dict[str, float],
        retry_ratio:   float = 0.15,
        renewal_ratio: float = 0.12,
        partial_ratio: float = 0.20,
    ) -> List[ScenarioSpec]:
        """
        Generate a mixed list of normal + anomaly specs in random order.

        Parameters
        ----------
        n_normal      : total normal sessions
        n_attack      : total attack sessions
        distribution  : {anomaly_type: fraction} — must sum to 1.0
        retry_ratio   : fraction of normal sessions that use the retry flow
        renewal_ratio : fraction of normal sessions that use the renewal flow
        partial_ratio : fraction of normal sessions that drop out early
                        (short, incomplete benign sessions)

        The remaining normal sessions use build_session_flow() (randomised
        access activity and ending). retry + renewal + partial must sum to
        <= 1.0. The partial sessions populate the low n_events range, and the
        randomised full sessions populate a broad both-parity range, so benign
        sessions overlap the anomaly sessions on session length and on the
        session-lifecycle outcomes (access-granted / clean-close) rather than
        being perfectly separable from them.

        Returns
        -------
        Shuffled list of ScenarioSpec objects (normal + anomaly interleaved).
        """
        if abs(sum(distribution.values()) - 1.0) > 1e-6:
            raise ValueError("attack distribution must sum to 1.0")
        if retry_ratio + renewal_ratio + partial_ratio > 1.0:
            raise ValueError("retry + renewal + partial ratios must sum to <= 1.0")

        specs: List[ScenarioSpec] = []

        # Normal — randomised full sessions plus retry / renewal / early-drop
        n_retry   = int(n_normal * retry_ratio)
        n_renewal = int(n_normal * renewal_ratio)
        n_partial = int(n_normal * partial_ratio)
        n_full    = n_normal - n_retry - n_renewal - n_partial

        for _ in range(n_full):
            specs.append(self.normal())
        for _ in range(n_retry):
            specs.append(self.normal_with_retry())
        for _ in range(n_renewal):
            specs.append(self.normal_with_renewal())
        for _ in range(n_partial):
            specs.append(self.normal_partial())

        # Attack — split by distribution
        counts = self._split_counts(n_attack, distribution)
        for atype, count in counts.items():
            for _ in range(count):
                specs.append(self.anomaly(atype))

        random.shuffle(specs)
        return specs

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _split_counts(total: int, distribution: Dict[str, float]) -> Dict[str, int]:
        """Convert fractions to integer counts, distributing rounding remainder."""
        counts   = {k: int(v * total) for k, v in distribution.items()}
        remainder = total - sum(counts.values())
        if remainder > 0:
            first = next(iter(counts))
            counts[first] += remainder
        return counts

    def summary(self, specs: List[ScenarioSpec]) -> Dict[str, int]:
        """Return a count summary of a batch of specs."""
        summary: Dict[str, int] = {}
        for s in specs:
            summary[s.scenario_type] = summary.get(s.scenario_type, 0) + 1
        return dict(sorted(summary.items()))