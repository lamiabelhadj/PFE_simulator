"""
simulator/state_machine.py
───────────────────────────
Transition table, validity checks, and anomaly injection.

Architecture
────────────
Two operating modes:

  NORMAL mode
    StateMachine.advance(event_type) looks up (current_state, event_type)
    in TRANSITIONS.  If the pair exists, the machine moves to the next state
    and returns it.  If not, it raises TransitionError — the caller can catch
    this to generate a labelled anomalous event.

  ANOMALY INJECTION mode
    StateMachine.get_anomaly_transition(anomaly_type) returns a
    (from_state, event_type) pair guaranteed NOT to be in TRANSITIONS.
    The caller then:
      1. sm.force(from_state)       — jump to the required predecessor state
      2. sm.advance(event_type)     — this raises TransitionError
      3. catch + label the event    — anomaly_label = anomaly_type

Transition table design
───────────────────────
Key   : (AuthState, EventType)  — current state + incoming event
Value : AuthState               — resulting state

Only valid normal-lifecycle transitions are in the table.
Every (state, event) pair not in TRANSITIONS is a potential anomaly.

Auto-blocking
─────────────
After 3 consecutive AUTH_FAILED transitions (configurable), the machine
automatically moves to BLOCKED.  This represents the gateway rate-limiting
a device after repeated failures.

Anomaly coverage
────────────────
9 anomaly types from the spec are mapped to invalid transitions:
  1. replay_token               6. impersonation
  2. nonce_reuse                7. identity_token_mismatch
  3. timestamp_inconsistency    8. abnormal_renewal
  4. access_without_auth        9. duplicate_sequence (documented, future)
  5. abnormal_failure_rate
"""

import random
from typing import Dict, List, Optional, Tuple

from simulator.event_model import AuthState, EventType


# ══════════════════════════════════════════════════════════════════════════════
# Custom exception
# ══════════════════════════════════════════════════════════════════════════════

class TransitionError(Exception):
    """Raised when an event type is not valid from the current state."""
    def __init__(self, from_state: AuthState, event_type: EventType):
        self.from_state = from_state
        self.event_type = event_type
        super().__init__(
            f"Invalid transition: '{from_state.value}' + '{event_type.value}'"
        )


# ══════════════════════════════════════════════════════════════════════════════
# TRANSITIONS — normal authentication lifecycle
# ══════════════════════════════════════════════════════════════════════════════

TRANSITIONS: Dict[Tuple[AuthState, EventType], AuthState] = {

    # ── Registration ──────────────────────────────────────────────────────────
    (AuthState.UNREGISTERED, EventType.REGISTRATION_REQUEST):  AuthState.REGISTERED,
    (AuthState.REGISTERED,   EventType.REGISTRATION_REQUEST):  AuthState.REGISTERED,   # idempotent re-reg (won't fail or cause error the state machine will stay in registered state because the device is already registered)
    (AuthState.REGISTERED,   EventType.REGISTRATION_CONFIRMED): AuthState.REGISTERED,  # server-side confirmation, state stays REGISTERED (matches FLOW_STATE_AFTER)

    # ── Authentication initiation ─────────────────────────────────────────────
    (AuthState.REGISTERED,    EventType.AUTHENTICATION_REQUEST): AuthState.AUTH_REQUESTED,
    (AuthState.TOKEN_EXPIRED, EventType.AUTHENTICATION_REQUEST): AuthState.AUTH_REQUESTED,
    (AuthState.AUTH_FAILED,   EventType.AUTHENTICATION_REQUEST): AuthState.AUTH_REQUESTED,

    # ── Challenge–response ────────────────────────────────────────────────────
    # Gateway sends challenge → state becomes CHALLENGE_ISSUED
    (AuthState.AUTH_REQUESTED,  EventType.CHALLENGE_SENT):   AuthState.CHALLENGE_ISSUED,
    # Server receives device nonce (challenge still open, device hasn't responded yet)
    (AuthState.CHALLENGE_ISSUED, EventType.NONCE_RECEIVED):  AuthState.CHALLENGE_ISSUED,
    # Device sends full response (nonce + computed answer)
    (AuthState.CHALLENGE_ISSUED, EventType.RESPONSE_SENT):   AuthState.RESPONSE_SENT,

    # ── Authentication result ─────────────────────────────────────────────────
    (AuthState.RESPONSE_SENT, EventType.AUTHENTICATION_SUCCESS): AuthState.AUTHENTICATED,
    (AuthState.RESPONSE_SENT, EventType.AUTHENTICATION_FAILURE): AuthState.AUTH_FAILED,

    # ── Token issuance ────────────────────────────────────────────────────────
    (AuthState.AUTHENTICATED,     EventType.TOKEN_ISSUED): AuthState.TOKEN_ISSUED,
    (AuthState.RENEWAL_REQUESTED, EventType.TOKEN_ISSUED): AuthState.TOKEN_ISSUED,

    # ── Token presentation & validation ───────────────────────────────────────
    (AuthState.TOKEN_ISSUED,    EventType.TOKEN_PRESENTED): AuthState.TOKEN_PRESENTED,
    (AuthState.TOKEN_PRESENTED, EventType.TOKEN_VALIDATED): AuthState.TOKEN_VALIDATED,
    (AuthState.TOKEN_PRESENTED, EventType.TOKEN_REJECTED):  AuthState.AUTH_FAILED,

    # ── Session open ──────────────────────────────────────────────────────────
    (AuthState.TOKEN_VALIDATED, EventType.SESSION_OPENED): AuthState.SESSION_OPEN,

    # ── Resource access (cycles within an open session) ───────────────────────
    (AuthState.SESSION_OPEN,     EventType.ACCESS_REQUEST): AuthState.ACCESS_REQUESTED,
    (AuthState.ACCESS_GRANTED,   EventType.ACCESS_REQUEST): AuthState.ACCESS_REQUESTED,
    (AuthState.ACCESS_DENIED,    EventType.ACCESS_REQUEST): AuthState.ACCESS_REQUESTED,
    (AuthState.ACCESS_REQUESTED, EventType.ACCESS_GRANTED): AuthState.ACCESS_GRANTED,
    (AuthState.ACCESS_REQUESTED, EventType.ACCESS_DENIED):  AuthState.ACCESS_DENIED,

    # ── Token renewal ─────────────────────────────────────────────────────────
    # Valid only from SESSION_OPEN or ACCESS_GRANTED — never before the token
    # is nearing expiry (temporal enforcement is in the event engine).
    (AuthState.SESSION_OPEN,   EventType.RENEWAL_REQUEST): AuthState.RENEWAL_REQUESTED,
    (AuthState.ACCESS_GRANTED, EventType.RENEWAL_REQUEST): AuthState.RENEWAL_REQUESTED,

    # ── Token expiry ──────────────────────────────────────────────────────────
    (AuthState.TOKEN_VALIDATED, EventType.TOKEN_EXPIRED): AuthState.TOKEN_EXPIRED,
    (AuthState.SESSION_OPEN,    EventType.TOKEN_EXPIRED): AuthState.TOKEN_EXPIRED,
    (AuthState.TOKEN_EXPIRED,   EventType.RENEWAL_REQUEST): AuthState.RENEWAL_REQUESTED,

    # ── Session close ─────────────────────────────────────────────────────────
    (AuthState.SESSION_OPEN,    EventType.SESSION_CLOSED): AuthState.REGISTERED,
    (AuthState.ACCESS_GRANTED,  EventType.SESSION_CLOSED): AuthState.REGISTERED,
    (AuthState.ACCESS_DENIED,   EventType.SESSION_CLOSED): AuthState.REGISTERED,
    (AuthState.TOKEN_VALIDATED, EventType.SESSION_CLOSED): AuthState.REGISTERED,

    # ── Retry ─────────────────────────────────────────────────────────────────
    (AuthState.AUTH_FAILED,   EventType.RETRY): AuthState.AUTH_REQUESTED,
    (AuthState.TOKEN_EXPIRED, EventType.RETRY): AuthState.AUTH_REQUESTED,
    (AuthState.ACCESS_DENIED, EventType.RETRY): AuthState.ACCESS_REQUESTED,

    # ── Timeout ───────────────────────────────────────────────────────────────
    (AuthState.AUTH_REQUESTED,   EventType.TIMEOUT): AuthState.REGISTERED,
    (AuthState.CHALLENGE_ISSUED, EventType.TIMEOUT): AuthState.REGISTERED,
    (AuthState.RESPONSE_SENT,    EventType.TIMEOUT): AuthState.REGISTERED,
    (AuthState.TOKEN_PRESENTED,  EventType.TIMEOUT): AuthState.AUTH_FAILED,
    (AuthState.SESSION_OPEN,     EventType.TIMEOUT): AuthState.REGISTERED,

    # ── Disconnect ────────────────────────────────────────────────────────────
    (AuthState.SESSION_OPEN,    EventType.DISCONNECT): AuthState.REGISTERED,
    (AuthState.ACCESS_GRANTED,  EventType.DISCONNECT): AuthState.REGISTERED,
    (AuthState.AUTHENTICATED,   EventType.DISCONNECT): AuthState.REGISTERED,
    (AuthState.TOKEN_VALIDATED, EventType.DISCONNECT): AuthState.REGISTERED,
}

# Total number of valid transitions
TRANSITION_COUNT = len(TRANSITIONS)


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY_TRANSITIONS — invalid (from_state, event_type) pairs per anomaly
# ══════════════════════════════════════════════════════════════════════════════
#
# Each entry maps an anomaly label to a list of (AuthState, EventType) pairs
# that are deliberately absent from TRANSITIONS.
#
# The event engine calls get_anomaly_transition(anomaly_type) to pick one,
# forces the machine into from_state, then calls advance(event_type) which
# raises TransitionError — the catch site creates the labelled anomalous event.

ANOMALY_TRANSITIONS: Dict[str, List[Tuple[AuthState, EventType]]] = {

    # 1. Token replay
    #    A token is presented outside the normal issuance → presentation window.
    "replay_token": [
        (AuthState.REGISTERED,   EventType.TOKEN_PRESENTED),   # no auth at all
        (AuthState.SESSION_OPEN, EventType.TOKEN_PRESENTED),   # re-present in live session
        (AuthState.AUTH_FAILED,  EventType.TOKEN_PRESENTED),   # present after failure
    ],

    # 2. Nonce reuse
    #    A NONCE_RECEIVED event when no challenge is active.
    "nonce_reuse": [
        (AuthState.REGISTERED,      EventType.NONCE_RECEIVED),
        (AuthState.AUTHENTICATED,   EventType.NONCE_RECEIVED),
        (AuthState.SESSION_OPEN,    EventType.NONCE_RECEIVED),
        (AuthState.TOKEN_VALIDATED, EventType.NONCE_RECEIVED),
    ],

    # 3. Timestamp inconsistency
    #    State-level representation: a response arrives before a challenge
    #    was ever issued.  Temporal enforcement (negative delay) is added
    "timestamp_inconsistency": [
        (AuthState.REGISTERED,    EventType.RESPONSE_SENT),
        (AuthState.AUTH_REQUESTED, EventType.RESPONSE_SENT),  # challenge not issued yet
    ],

    # 4. Access without prior authentication
    #    ACCESS_REQUEST arrives before any authentication has completed.
    "access_without_auth": [
        (AuthState.UNREGISTERED,     EventType.ACCESS_REQUEST),
        (AuthState.REGISTERED,       EventType.ACCESS_REQUEST),
        (AuthState.AUTH_REQUESTED,   EventType.ACCESS_REQUEST),
        (AuthState.CHALLENGE_ISSUED, EventType.ACCESS_REQUEST),
        (AuthState.RESPONSE_SENT,    EventType.ACCESS_REQUEST),
    ],

    # 5. Abnormal failure rate
    #    Auth attempted from BLOCKED state — device should have been locked out.
    "abnormal_failure_rate": [
        (AuthState.BLOCKED, EventType.AUTHENTICATION_REQUEST),
        (AuthState.BLOCKED, EventType.REGISTRATION_REQUEST),
    ],

    # 6. Device impersonation
    #    Session opened without the token validation step being completed.
    #    The identity_claim vs device_id mismatch is checked at the attribute
    "impersonation": [
        (AuthState.AUTH_FAILED,      EventType.SESSION_OPENED),
        (AuthState.TOKEN_PRESENTED,  EventType.SESSION_OPENED),  # skip validation
    ],

    # 7. Identity–token–session mismatch
    #    Session opened without a token ever being presented.
    "identity_token_mismatch": [
        (AuthState.REGISTERED,    EventType.SESSION_OPENED),
        (AuthState.AUTHENTICATED, EventType.SESSION_OPENED),   # token not yet presented
    ],

    # 8. Abnormal renewal frequency
    #    Renewal requested when the token was just issued or is still fresh.
    "abnormal_renewal": [
        (AuthState.TOKEN_ISSUED,    EventType.RENEWAL_REQUEST),
        (AuthState.TOKEN_VALIDATED, EventType.RENEWAL_REQUEST),
        (AuthState.TOKEN_PRESENTED, EventType.RENEWAL_REQUEST),
    ],

    # 9. Full sequence duplication (documented for future implementation)
    #    A complete auth sequence replayed while a session is already open.
    "duplicate_sequence": [
        (AuthState.SESSION_OPEN,  EventType.REGISTRATION_REQUEST),
        (AuthState.AUTHENTICATED, EventType.REGISTRATION_REQUEST),
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# StateMachine class — per-session instance
# ══════════════════════════════════════════════════════════════════════════════

class StateMachine:
    """
    Tracks the authentication state of one device/session.

    One instance is created per simulated session by the event engine.

    Normal usage
    ────────────
        sm = StateMachine()
        sm.advance(EventType.REGISTRATION_REQUEST)   # → REGISTERED
        sm.advance(EventType.AUTHENTICATION_REQUEST) # → AUTH_REQUESTED
        ...

    Anomaly injection
    ─────────────────
        from_state, event = sm.get_anomaly_transition("access_without_auth")
        sm.force(from_state)
        try:
            sm.advance(event)
        except TransitionError as e:
            # create AuthEvent with anomaly_label = "access_without_auth"

    Auto-blocking
    ─────────────
    Three consecutive AUTH_FAILED outcomes → state becomes BLOCKED automatically.
    """

    MAX_CONSECUTIVE_FAILURES = 3

    def __init__(self, initial_state: AuthState = AuthState.UNREGISTERED):
        self.state:        AuthState = initial_state
        self.history:      List[Tuple[AuthState, EventType, AuthState]] = []
        self._fail_count:  int = 0

    # ── Core transition ───────────────────────────────────────────────────────

    def advance(self, event_type: EventType) -> AuthState:
        """
        Attempt the transition (current_state, event_type).

        Returns the new state on success.
        Raises TransitionError if the pair is not in TRANSITIONS.

        Side effects:
          - Appends (previous, event, new) to self.history.
          - Increments _fail_count on AUTH_FAILED; resets on any other state.
          - Automatically moves to BLOCKED after MAX_CONSECUTIVE_FAILURES.
        """
        key = (self.state, event_type)
        if key not in TRANSITIONS:
            raise TransitionError(self.state, event_type)

        previous   = self.state
        self.state = TRANSITIONS[key]

        # Auto-block after repeated failures.
        # Counter increments on AUTH_FAILED, resets only on AUTHENTICATED.
        # Intermediate states (RESPONSE_SENT etc.) do not clear it so that
        # repeated attempts across multiple challenge-response cycles accumulate.
        if self.state == AuthState.AUTH_FAILED:
            self._fail_count += 1
            if self._fail_count >= self.MAX_CONSECUTIVE_FAILURES:
                self.state = AuthState.BLOCKED
        elif self.state == AuthState.AUTHENTICATED:
            self._fail_count = 0

        self.history.append((previous, event_type, self.state))
        return self.state

    # ── Validation helpers ────────────────────────────────────────────────────

    def is_valid(self, event_type: EventType) -> bool:
        """True if event_type is a valid transition from the current state."""
        return (self.state, event_type) in TRANSITIONS

    def peek(self, event_type: EventType) -> Optional[AuthState]:
        """Return the would-be next state without committing, or None if invalid."""
        return TRANSITIONS.get((self.state, event_type))

    def reachable_events(self) -> List[EventType]:
        """All EventTypes that are valid from the current state."""
        return [et for (st, et) in TRANSITIONS if st == self.state]

    # ── Force / anomaly injection ─────────────────────────────────────────────

    def force(self, state: AuthState) -> None:
        """
        Jump to an arbitrary state without validation.
        Used to set up the prerequisite state before injecting an anomaly.
        The jump is logged in history as a DISCONNECT event for traceability.
        """
        self.history.append((self.state, EventType.DISCONNECT, state))
        self.state = state

    def get_anomaly_transition(self, anomaly_type: str) -> Tuple[AuthState, EventType]:
        """
        Return a (from_state, event_type) pair that violates TRANSITIONS
        for the given anomaly_type.

        Picks randomly among the candidates for variety in the dataset.

        Raises ValueError for unknown anomaly types.
        """
        candidates = ANOMALY_TRANSITIONS.get(anomaly_type)
        if not candidates:
            raise ValueError(
                f"Unknown anomaly type: '{anomaly_type}'. "
                f"Valid types: {list(ANOMALY_TRANSITIONS.keys())}"
            )
        return random.choice(candidates)

    # ── Status properties ─────────────────────────────────────────────────────

    @property
    def is_blocked(self) -> bool:
        return self.state == AuthState.BLOCKED

    @property
    def is_terminal(self) -> bool:
        """True if no further normal transitions are possible."""
        return not self.reachable_events()

    @property
    def step_count(self) -> int:
        return len(self.history)

    def __repr__(self) -> str:
        return (
            f"StateMachine(state={self.state.value}, "
            f"steps={self.step_count}, "
            f"fail_count={self._fail_count})"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Module-level convenience functions
# ══════════════════════════════════════════════════════════════════════════════

def is_valid_transition(from_state: AuthState, event_type: EventType) -> bool:
    """True if (from_state, event_type) is in the normal transition table."""
    return (from_state, event_type) in TRANSITIONS


def get_transition(from_state: AuthState, event_type: EventType) -> Optional[AuthState]:
    """Return the next state for (from_state, event_type), or None if invalid."""
    return TRANSITIONS.get((from_state, event_type))


def all_anomaly_types() -> List[str]:
    """Return all supported anomaly label strings."""
    return list(ANOMALY_TRANSITIONS.keys())