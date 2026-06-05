"""
simulator/engines/event_engine.py
───────────────────────────────────
Layer 2 of 3 — Event Engine

Responsibility: execute a ScenarioSpec into a correlated AuthEvent sequence.

For each scenario the engine:
  1. Creates a fresh StateMachine.
  2. Generates a shared session_id, token_id, and nonce for consistency.
  3. Iterates through the spec's normal_steps, calling sm.advance() and
     emitting one AuthEvent per step with realistic timing.
  4. For anomaly specs: at injection_position, forces the SM to
     injection_from_state and fires injection_event → catches TransitionError
     → emits a labelled anomalous AuthEvent (state does NOT advance).
  5. Returns the complete List[AuthEvent] = one correlated session sequence.

Three session properties guaranteed
─────────────────────────────────────
  Temporal consistency
    Every event's timestamp = previous_timestamp + delay.
    delay_since_previous_event is stored on each event.
    Delays are sampled from per-event-type profiles (see DELAY_PROFILE).

  State dependency
    Events are only created after sm.advance() validates the transition.
    The previous_state and new_state on each event are taken directly from
    the StateMachine — never invented.

  Inter-entity consistency
    session_id  — same across all events in the sequence.
    token_id    — generated at TOKEN_ISSUED, carried through TOKEN_PRESENTED
                  and TOKEN_VALIDATED.  None on all other events.
    nonce       — generated at CHALLENGE_SENT, carried through NONCE_RECEIVED
                  and RESPONSE_SENT.  None on all other events.
    identity_claim — set to a victim device_id on impersonation anomalies.
"""

import hashlib
import random
import time
import uuid
from typing import Dict, List, Optional, Tuple

from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.state_machine import StateMachine, TransitionError
from simulator.engines.scenario_engine import ScenarioSpec


# ══════════════════════════════════════════════════════════════════════════════
# Delay profiles — seconds between consecutive events (mean, std)
# ══════════════════════════════════════════════════════════════════════════════
#
# Normal profile: realistic IoT authentication timing.
# Attack profile: attacker moves faster (smaller mean) or is erratic (larger std).

DELAY_PROFILE_NORMAL: Dict[EventType, Tuple[float, float]] = {
    EventType.REGISTRATION_REQUEST:   (0.0,  0.0),    # first event, no delay
    EventType.REGISTRATION_CONFIRMED: (0.08, 0.02),
    EventType.AUTHENTICATION_REQUEST: (0.5,  0.3),    # device waits a moment
    EventType.CHALLENGE_SENT:         (0.07, 0.02),
    EventType.NONCE_RECEIVED:         (0.15, 0.05),   # device computes nonce
    EventType.RESPONSE_SENT:          (0.25, 0.08),   # device computes response
    EventType.AUTHENTICATION_SUCCESS: (0.06, 0.02),
    EventType.AUTHENTICATION_FAILURE: (0.06, 0.02),
    EventType.TOKEN_ISSUED:           (0.08, 0.02),
    EventType.TOKEN_PRESENTED:        (0.12, 0.04),
    EventType.TOKEN_VALIDATED:        (0.06, 0.02),
    EventType.SESSION_OPENED:         (0.05, 0.01),
    EventType.ACCESS_REQUEST:         (2.0,  1.5),    # device waits before accessing
    EventType.ACCESS_GRANTED:         (0.05, 0.01),
    EventType.ACCESS_DENIED:          (0.05, 0.01),
    EventType.SESSION_CLOSED:         (30.0, 20.0),   # session lasts a while
    EventType.RENEWAL_REQUEST:        (240.0, 30.0),  # near token expiry
    EventType.TOKEN_EXPIRED:          (300.0, 10.0),  # token lifetime
    EventType.RETRY:                  (1.0,  0.5),
    EventType.TIMEOUT:                (30.0, 5.0),
    EventType.DISCONNECT:             (5.0,  2.0),
    EventType.NONCE_RECEIVED:         (0.15, 0.05),
}

DELAY_PROFILE_ATTACK: Dict[EventType, Tuple[float, float]] = {
    # Attackers are typically faster and more erratic
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
    EventType.RENEWAL_REQUEST:        (5.0,  2.0),   # abnormally frequent
    EventType.TOKEN_EXPIRED:          (300.0, 10.0),
    EventType.RETRY:                  (0.2,  0.1),
    EventType.TIMEOUT:                (30.0, 5.0),
    EventType.DISCONNECT:             (1.0,  0.5),
}


# ══════════════════════════════════════════════════════════════════════════════
# Events that carry a token_id
# ══════════════════════════════════════════════════════════════════════════════

TOKEN_CARRYING_EVENTS = {
    EventType.TOKEN_ISSUED,
    EventType.TOKEN_PRESENTED,
    EventType.TOKEN_VALIDATED,
    EventType.TOKEN_REJECTED,
    EventType.RENEWAL_REQUEST,
    EventType.SESSION_OPENED,
    EventType.ACCESS_REQUEST,
    EventType.ACCESS_GRANTED,
    EventType.ACCESS_DENIED,
}

NONCE_CARRYING_EVENTS = {
    EventType.CHALLENGE_SENT,
    EventType.NONCE_RECEIVED,
    EventType.RESPONSE_SENT,
}


# ══════════════════════════════════════════════════════════════════════════════
# EventEngine
# ══════════════════════════════════════════════════════════════════════════════

class EventEngine:
    """
    Executes a ScenarioSpec into a correlated List[AuthEvent].

    One EventEngine instance can process many specs sequentially.
    State (nonce, token, SM) is reset per execute() call.

    Parameters
    ----------
    device_id      : device identifier (carried on all events)
    gateway_id     : gateway identifier
    auth_server_id : auth server identifier
    broker_id      : MQTT broker identifier (optional)
    start_time     : Unix timestamp for the first event (default: now)
    """

    def __init__(
        self,
        device_id:      str,
        gateway_id:     str,
        auth_server_id: str,
        broker_id:      Optional[str] = None,
        start_time:     Optional[float] = None,
    ):
        self.device_id      = device_id
        self.gateway_id     = gateway_id
        self.auth_server_id = auth_server_id
        self.broker_id      = broker_id
        self.start_time     = start_time or time.time()

    # ══════════════════════════════════════════════════════════════════════════
    # Main entry point
    # ══════════════════════════════════════════════════════════════════════════

    def execute(self, spec: ScenarioSpec) -> List[AuthEvent]:
        """
        Execute one ScenarioSpec and return the correlated event sequence.

        Normal scenario  → runs all normal_steps, returns clean sequence.
        Anomaly scenario → runs normal_steps[:injection_position], then injects
                           the anomalous event and stops.

        All events share the same scenario_id and session_id.
        token_id and nonce are propagated across the relevant event types.
        """
        sm         = StateMachine()
        events:    List[AuthEvent] = []
        session_id = str(uuid.uuid4())
        token_id:  Optional[str] = None
        nonce:     Optional[str] = None
        current_ts = self.start_time
        retry_count = 0

        is_attack  = spec.is_anomaly
        profile    = DELAY_PROFILE_ATTACK if is_attack else DELAY_PROFILE_NORMAL

        # ── Run normal steps (full or up to injection_position) ───────────────
        steps_to_run = (
            spec.normal_steps[:spec.injection_position]
            if spec.is_anomaly
            else spec.normal_steps
        )

        for event_type in steps_to_run:
            delay      = self._sample_delay(event_type, profile)
            current_ts = current_ts + delay

            prev_state = sm.state

            # Determine result before advancing SM
            result, failure_reason = self._outcome(event_type, is_anomaly=False)

            try:
                new_state = sm.advance(event_type)
            except TransitionError:
                # Should not happen in normal steps — log and continue
                new_state = prev_state
                result    = EventResult.FAILURE
                failure_reason = "unexpected_transition_error"

            # Update shared context
            if event_type == EventType.TOKEN_ISSUED:
                token_id = str(uuid.uuid4())
            if event_type == EventType.CHALLENGE_SENT:
                nonce = hashlib.blake2s(uuid.uuid4().bytes).hexdigest()[:16]
            if event_type in {EventType.AUTHENTICATION_FAILURE, EventType.TOKEN_REJECTED}:
                retry_count += 1

            ev = self._make_event(
                event_type  = event_type,
                prev_state  = prev_state,
                new_state   = new_state,
                result      = result,
                failure_reason = failure_reason,
                session_id  = session_id,
                scenario_id = spec.scenario_id,
                timestamp   = current_ts,
                delay       = delay,
                token_id    = token_id if event_type in TOKEN_CARRYING_EVENTS else None,
                nonce       = nonce    if event_type in NONCE_CARRYING_EVENTS  else None,
                retry_count = retry_count,
                anomaly_label = None,
            )
            events.append(ev)

        # ── Anomaly injection ─────────────────────────────────────────────────
        if spec.is_anomaly:
            delay      = self._sample_delay(spec.injection_event, profile)
            current_ts = current_ts + delay

            # For replay / timestamp anomaly: inject with an old timestamp
            if spec.anomaly_type == "timestamp_inconsistency":
                current_ts = current_ts - random.uniform(400, 900)  # negative delay

            prev_state = sm.state
            sm.force(spec.injection_from_state)  # jump to required from-state

            # The advance will raise TransitionError — that IS the anomaly
            try:
                sm.advance(spec.injection_event)
                new_state = sm.state
            except TransitionError:
                new_state = spec.injection_from_state  # state did not advance

            # Identity claim: for impersonation, claim a different device_id
            identity_claim = None
            if spec.anomaly_type == "impersonation":
                identity_claim = f"victim-{str(uuid.uuid4())[:8]}"

            # For replay: keep the token_id from the captured session
            # (in the full pipeline the runner injects the stolen token here)
            inj_token_id = token_id if spec.injection_event in TOKEN_CARRYING_EVENTS else None

            ev = self._make_event(
                event_type     = spec.injection_event,
                prev_state     = spec.injection_from_state,
                new_state      = new_state,
                result         = EventResult.FAILURE,
                failure_reason = f"invalid_transition_{spec.anomaly_type}",
                session_id     = session_id,
                scenario_id    = spec.scenario_id,
                timestamp      = current_ts,
                delay          = delay,
                token_id       = inj_token_id,
                nonce          = nonce if spec.injection_event in NONCE_CARRYING_EVENTS else None,
                retry_count    = retry_count,
                anomaly_label  = spec.anomaly_type,
                identity_claim = identity_claim,
            )
            events.append(ev)

        return events

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
        token_id:       Optional[str],
        nonce:          Optional[str],
        retry_count:    int,
        anomaly_label:  Optional[str],
        identity_claim: Optional[str] = None,
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
            nonce                      = nonce,
            retry_count                = retry_count,
            anomaly_label              = anomaly_label,
            identity_claim             = identity_claim,
            source_context             = "attack" if anomaly_label else "normal",
        )

    @staticmethod
    def _sample_delay(
        event_type: EventType,
        profile:    Dict[EventType, Tuple[float, float]],
    ) -> float:
        """Sample a non-negative delay from the Gaussian profile for event_type."""
        mean, std = profile.get(event_type, (0.1, 0.05))
        return max(0.0, random.gauss(mean, std))

    @staticmethod
    def _outcome(
        event_type: EventType,
        is_anomaly: bool,
    ) -> Tuple[EventResult, Optional[str]]:
        """
        Determine the result and optional failure_reason for a normal event.
        Most normal events succeed.  Auth failures are possible with low probability.
        """
        failure_events = {
            EventType.AUTHENTICATION_FAILURE,
            EventType.TOKEN_REJECTED,
            EventType.ACCESS_DENIED,
        }
        if event_type in failure_events:
            return EventResult.FAILURE, event_type.value

        # Small chance of spurious failure even in normal flow
        if not is_anomaly and random.random() < 0.02:
            return EventResult.FAILURE, "transient_error"

        return EventResult.SUCCESS, None