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

Normal flow (13 steps)
───────────────────────
  REGISTRATION_REQUEST → REGISTRATION_CONFIRMED → AUTHENTICATION_REQUEST
  → CHALLENGE_SENT → NONCE_RECEIVED → RESPONSE_SENT → AUTHENTICATION_SUCCESS
  → TOKEN_ISSUED → TOKEN_PRESENTED → TOKEN_VALIDATED → SESSION_OPENED
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

NORMAL_FLOW: List[EventType] = [
    EventType.REGISTRATION_REQUEST,
    EventType.REGISTRATION_CONFIRMED,
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

# ── State checkpoints within NORMAL_FLOW ─────────────────────────────────────
# Maps EventType → the AuthState the SM will be in AFTER that event fires.
# Used by the scenario engine to pick a sensible injection_position.
FLOW_STATE_AFTER: Dict[EventType, AuthState] = {
    EventType.REGISTRATION_REQUEST:   AuthState.REGISTERED,
    EventType.REGISTRATION_CONFIRMED: AuthState.REGISTERED,
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
    EventType.SESSION_CLOSED:         AuthState.REGISTERED,
}

# ── How many normal steps to run before injecting each anomaly ────────────────
# The injection_position selects the point in NORMAL_FLOW where the anomaly
# is inserted.  The value is the number of steps executed BEFORE injection.
# Chosen so the StateMachine reaches a state close to injection_from_state.
ANOMALY_INJECTION_POSITION: Dict[str, int] = {
    "replay_token":             2,   # after REGISTRATION_CONFIRMED (state: REGISTERED)
    "nonce_reuse":              7,   # after AUTHENTICATION_SUCCESS  (state: AUTHENTICATED)
    "timestamp_inconsistency":  2,   # after REGISTRATION_CONFIRMED (state: REGISTERED)
    "access_without_auth":      2,   # after REGISTRATION_CONFIRMED (state: REGISTERED)
    "abnormal_failure_rate":    6,   # after RESPONSE_SENT          (state: RESPONSE_SENT)
    "impersonation":            6,   # after RESPONSE_SENT          (state: RESPONSE_SENT)
    "identity_token_mismatch":  2,   # after REGISTRATION_CONFIRMED (state: REGISTERED)
    "abnormal_renewal":         8,   # after TOKEN_PRESENTED        (state: TOKEN_PRESENTED)
    "duplicate_sequence":      10,   # after SESSION_OPENED         (state: SESSION_OPEN)
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
        """Generate one normal (benign) scenario spec."""
        return ScenarioSpec(
            scenario_id   = str(uuid.uuid4()),
            scenario_type = "normal",
            is_anomaly    = False,
            normal_steps  = list(NORMAL_FLOW),
        )

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

        return ScenarioSpec(
            scenario_id          = str(uuid.uuid4()),
            scenario_type        = anomaly_type,
            is_anomaly           = True,
            normal_steps         = list(NORMAL_FLOW),
            anomaly_type         = anomaly_type,
            injection_position   = position,
            injection_from_state = from_state,
            injection_event      = event,
        )

    # ── Batch generation ───────────────────────────────────────────────────────

    def batch(
        self,
        n_normal:     int,
        n_attack:     int,
        distribution: Dict[str, float],
    ) -> List[ScenarioSpec]:
        """
        Generate a mixed list of normal + anomaly specs in random order.

        Parameters
        ----------
        n_normal     : number of normal sessions
        n_attack     : total attack sessions
        distribution : {anomaly_type: fraction} — must sum to 1.0

        Returns
        -------
        Shuffled list of ScenarioSpec objects (normal + anomaly interleaved).
        """
        if abs(sum(distribution.values()) - 1.0) > 1e-6:
            raise ValueError("attack distribution must sum to 1.0")

        specs: List[ScenarioSpec] = []

        # Normal
        for _ in range(n_normal):
            specs.append(self.normal())

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