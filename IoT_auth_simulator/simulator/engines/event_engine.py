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
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.state_machine import StateMachine, TransitionError
from simulator.engines.scenario_engine import ScenarioSpec


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

# ── Delay profiles (mean, std) in seconds ─────────────────────────────────────
DELAY_PROFILE_NORMAL: Dict[EventType, Tuple[float, float]] = {
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
    EventType.NONCE_RECEIVED:         (0.15, 0.05),
}

DELAY_PROFILE_ATTACK: Dict[EventType, Tuple[float, float]] = {
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
    attack_type:  str   # "normal" | anomaly_label
    attack_phase: str   # event_type of injected anomaly | "none"
    severity:     str   # none | medium | high | critical

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
        device_id:      str,
        gateway_id:     str,
        auth_server_id: str,
        broker_id:      Optional[str]   = None,
        source_ip:      Optional[str]   = None,
        battery_level:  Optional[float] = None,
        start_time:     Optional[float] = None,
    ):
        self.device_id      = device_id
        self.gateway_id     = gateway_id
        self.auth_server_id = auth_server_id
        self.broker_id      = broker_id
        self.source_ip      = source_ip or f"10.0.1.{random.randint(1, 254)}"
        self.battery_level  = battery_level if battery_level is not None \
                              else round(random.uniform(0.0, 100.0), 1)
        self.start_time     = start_time or time.time()

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
        token_id:  Optional[str] = None
        nonce:     Optional[str] = None
        current_ts = self.start_time
        retry_count = 0
        is_attack  = spec.is_anomaly
        profile    = DELAY_PROFILE_ATTACK if is_attack else DELAY_PROFILE_NORMAL

        # ── Accumulators for SessionContext ───────────────────────────────────
        ctx: Dict = {
            "s1_latency_ms": 0.0, "s2_latency_ms": 0.0,
            "s3_latency_ms": 0.0, "s4_latency_ms": 0.0,
            "s5_latency_ms": 0.0, "s6_latency_ms": 0.0,
            "auth_latency_ms":   0.0,
            "pairing_latency_ms": 0.0,
            "auth_result":        0,
            "credential_status":  1,
            "connack_code":       "pending",
            "failed_auth_count":  0,
            "authorization_result": 0,
            "topic_scope_violation": 0,
            "re_auth_required":   0,
            "source_ip_change":   0,
            "session_present":    0,
        }

        # ── Run normal steps ──────────────────────────────────────────────────
        steps_to_run = (
            spec.normal_steps[:spec.injection_position]
            if spec.is_anomaly else spec.normal_steps
        )

        for event_type in steps_to_run:
            delay      = self._sample_delay(event_type, profile)
            current_ts = current_ts + delay
            prev_state = sm.state
            result, failure_reason = self._outcome(event_type, is_anomaly=False)

            try:
                new_state = sm.advance(event_type)
            except TransitionError:
                new_state      = prev_state
                result         = EventResult.FAILURE
                failure_reason = "unexpected_transition_error"

            # ── Update shared token/nonce context ─────────────────────────────
            if event_type == EventType.TOKEN_ISSUED:
                token_id = str(uuid.uuid4())
            if event_type == EventType.CHALLENGE_SENT:
                nonce = hashlib.blake2s(uuid.uuid4().bytes).hexdigest()[:16]
            if event_type in {EventType.AUTHENTICATION_FAILURE, EventType.TOKEN_REJECTED}:
                retry_count          += 1
                ctx["failed_auth_count"] += 1

            # ── Capture step latencies ────────────────────────────────────────
            delay_ms = delay * 1000
            if event_type == EventType.REGISTRATION_REQUEST:
                ctx["s1_latency_ms"] = round(delay_ms, 2)
            elif event_type == EventType.CHALLENGE_SENT:
                ctx["s2_latency_ms"]      = round(delay_ms, 2)
                ctx["pairing_latency_ms"] = round(delay_ms, 2)
            elif event_type in {EventType.AUTHENTICATION_SUCCESS,
                                 EventType.AUTHENTICATION_FAILURE}:
                ctx["s3_latency_ms"]   = round(delay_ms, 2)
                ctx["auth_latency_ms"] = round(delay_ms, 2)
                ctx["auth_result"]     = 1 if event_type == EventType.AUTHENTICATION_SUCCESS else 0
                ctx["connack_code"]    = "success" if ctx["auth_result"] else failure_reason or "auth_failure"
                ctx["credential_status"] = 1 if ctx["auth_result"] else 0
            elif event_type == EventType.TOKEN_ISSUED:
                ctx["s4_latency_ms"] = round(delay_ms, 2)
            elif event_type == EventType.SESSION_OPENED:
                ctx["s5_latency_ms"]        = round(delay_ms, 2)
                ctx["authorization_result"] = 1
                ctx["session_present"]      = 1
            elif event_type == EventType.RENEWAL_REQUEST:
                ctx["s6_latency_ms"]    = round(delay_ms, 2)
                ctx["re_auth_required"] = 1
            elif event_type == EventType.ACCESS_DENIED:
                ctx["topic_scope_violation"] = 1 if random.random() < 0.3 else 0

            ev = self._make_event(
                event_type=event_type, prev_state=prev_state,
                new_state=new_state, result=result,
                failure_reason=failure_reason, session_id=session_id,
                scenario_id=spec.scenario_id, timestamp=current_ts,
                delay=delay, retry_count=retry_count,
                token_id=token_id if event_type in TOKEN_CARRYING_EVENTS else None,
                nonce=nonce if event_type in NONCE_CARRYING_EVENTS else None,
                anomaly_label=None,
            )
            events.append(ev)

        # ── Anomaly injection ─────────────────────────────────────────────────
        if spec.is_anomaly:
            delay      = self._sample_delay(spec.injection_event, profile)
            current_ts = current_ts + delay

            if spec.anomaly_type == "timestamp_inconsistency":
                current_ts = current_ts - random.uniform(400, 900)

            prev_state = sm.state
            sm.force(spec.injection_from_state)

            try:
                sm.advance(spec.injection_event)
                new_state = sm.state
            except TransitionError:
                new_state = spec.injection_from_state

            identity_claim = None
            if spec.anomaly_type == "impersonation":
                identity_claim           = f"victim-{str(uuid.uuid4())[:8]}"
                ctx["source_ip_change"]  = 1
                ctx["credential_status"] = 0

            if spec.anomaly_type in {"replay_token", "identity_token_mismatch"}:
                ctx["credential_status"] = 0

            ev = self._make_event(
                event_type=spec.injection_event, prev_state=spec.injection_from_state,
                new_state=new_state, result=EventResult.FAILURE,
                failure_reason=f"invalid_transition_{spec.anomaly_type}",
                session_id=session_id, scenario_id=spec.scenario_id,
                timestamp=current_ts, delay=delay, retry_count=retry_count,
                token_id=token_id if spec.injection_event in TOKEN_CARRYING_EVENTS else None,
                nonce=nonce if spec.injection_event in NONCE_CARRYING_EVENTS else None,
                anomaly_label=spec.anomaly_type,
                identity_claim=identity_claim,
            )
            events.append(ev)

        # ── Build SessionContext ───────────────────────────────────────────────
        context = self._build_context(spec, events, ctx)
        return events, context

    # ══════════════════════════════════════════════════════════════════════════
    # SessionContext builder
    # ══════════════════════════════════════════════════════════════════════════

    def _build_context(
        self,
        spec:   ScenarioSpec,
        events: List[AuthEvent],
        ctx:    Dict,
    ) -> SessionContext:
        is_attack   = spec.is_anomaly
        anomaly_lbl = spec.anomaly_type or "normal"

        # ── Network features ──────────────────────────────────────────────────
        if is_attack:
            tcp_rtt    = max(1.0, random.gauss(8.0,  30.0))
            pkt_rate   = max(1.0, random.gauss(350.0, 80.0))
        else:
            tcp_rtt    = max(1.0, random.gauss(20.0, 5.0))
            pkt_rate   = max(0.1, random.gauss(5.0,  1.5))

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

        if is_attack:
            msg_rate = max(1.0, random.gauss(350.0, 80.0))
            keep_alive = 10
        else:
            msg_rate   = max(0.1, random.gauss(1.0, 0.3))
            keep_alive = 60

        session_dur = max(0.0, events[-1].timestamp - events[0].timestamp)
        byte_rate   = round((msg_rate * payload_size), 2)

        # ── Trust score (degrades with failures) ──────────────────────────────
        trust = max(0.0, 0.8 - ctx["failed_auth_count"] * 0.15)
        replay_viol = int(
            anomaly_lbl in {"replay_token", "nonce_reuse", "timestamp_inconsistency"}
        )
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
        else:
            gw_decision = "session_valid"

        # ── Claimed device id ─────────────────────────────────────────────────
        anomaly_events = [e for e in events if e.anomaly_label]
        claimed_id = (
            anomaly_events[0].identity_claim
            if anomaly_events and anomaly_events[0].identity_claim
            else self.device_id
        )

        # ── Attack labels ─────────────────────────────────────────────────────
        attack_phase = (
            anomaly_events[0].event_type.value if anomaly_events else "none"
        )

        return SessionContext(
            # Identity
            claimed_device_id       = claimed_id,
            source_ip               = self.source_ip,
            registered_device       = ctx["credential_status"],
            source_connection_count = random.randint(1, 10),
            source_diversity        = 1 + ctx["source_ip_change"],
            battery_level           = self.battery_level,
            # Network
            tcp_flags               = "SYN,ACK" if not is_attack else "SYN",
            connection_duration     = conn_duration,
            tcp_rtt                 = round(tcp_rtt, 2),
            packet_rate             = round(pkt_rate, 3),
            inter_arrival_time      = inter_arrival,
            frame_length            = frame_len,
            tcp_segment_len         = seg_len,
            pairing_result          = 1 if not is_attack else 0,
            pairing_latency_ms      = ctx["pairing_latency_ms"],
            # Auth
            credential_status       = ctx["credential_status"],
            mqtt_msg_type           = "CONNECT",
            connect_flags           = 0xC2,
            clean_session           = 1,
            username_present        = 1,
            password_length         = 64,
            keep_alive              = keep_alive,
            mqtt_version            = 5,
            connack_code            = ctx["connack_code"],
            auth_result             = ctx["auth_result"],
            auth_latency_ms         = ctx["auth_latency_ms"],
            failed_auth_count       = ctx["failed_auth_count"],
            # Authorization
            requested_topic         = topic,
            topic_length            = len(topic),
            operation               = "pub_sub",
            requested_qos           = qos_level,
            granted_qos             = qos_level,
            authorization_result    = ctx["authorization_result"],
            topic_scope_violation   = ctx["topic_scope_violation"],
            retain_flag             = 0,
            # MQTT session
            message_id              = random.randint(1, 65535),
            duplicate_flag          = 0,
            payload_length          = payload_size,
            payload_hash            = payload_hash,
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
            attack_type             = anomaly_lbl,
            attack_phase            = attack_phase,
            severity                = SEVERITY_MAP.get(anomaly_lbl, "none"),
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
        if not is_anomaly and random.random() < 0.02:
            return EventResult.FAILURE, "transient_error"
        return EventResult.SUCCESS, None