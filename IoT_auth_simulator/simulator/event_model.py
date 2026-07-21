"""
simulator/event_model.py
─────────────────────────
Defines the two core enumerations and the AuthEvent dataclass that form
the backbone of the simulator.

Design rationale
────────────────
The previous version produced flat feature rows (one dict per session).
The new model produces *sequences of correlated events* — each event carries
its own state transition, timing, identity context, and anomaly label so that
ML models can reason about order, timing, and identity consistency, not just
aggregate per-session statistics.

Three properties every event sequence must satisfy:
  1. Temporal dynamics   — real delays, retries, expirations, nonce lifetimes
  2. State dependencies  — events are only valid in certain predecessor states
  3. Inter-entity consistency — token_id / session_id / device_id cross-checked

Public API
──────────
  EventType    — 27 event types covering the full authentication lifecycle
  AuthState    — 23 device/session states
  EventResult  — success | failure | pending
  AuthEvent    — dataclass for one event in a correlated sequence
"""

import uuid
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ══════════════════════════════════════════════════════════════════════════════
# EventType — 27 event types
# ══════════════════════════════════════════════════════════════════════════════

class EventType(str, Enum):
    """
    Every observable action in the authentication lifecycle.

    Inherits from str so values serialise to JSON without extra conversion
    and can be compared directly to string literals in tests.

    Six-phase lifecycle mapping (discovery → pairing → enrollment → authorization
    → MQTT session → re-authentication), matching the functional model:
    ─────────────
    Discovery    : DISCOVERY, GATEWAY_ADVERTISEMENT
    Pairing      : PAIRING_REQUEST, PAIRING_RESPONSE          (ECDH channel)
    Enrollment   : ENROLLMENT_REQUEST, ENROLLMENT_CONFIRMED   (identity recorded)
    Registration : REGISTRATION_REQUEST, REGISTRATION_CONFIRMED
                   (legacy coarse alias for the discovery→enrollment span; kept
                    for backward compatibility with earlier scenarios / datasets)
    Auth         : AUTHENTICATION_REQUEST, CHALLENGE_SENT, NONCE_RECEIVED,
                   RESPONSE_SENT, AUTHENTICATION_SUCCESS, AUTHENTICATION_FAILURE
    Token        : TOKEN_ISSUED, TOKEN_PRESENTED, TOKEN_VALIDATED,
                   TOKEN_REJECTED, RENEWAL_REQUEST, TOKEN_EXPIRED
    Session      : SESSION_OPENED, SESSION_CLOSED
    Resource     : ACCESS_REQUEST, ACCESS_GRANTED, ACCESS_DENIED
    Control      : RETRY, TIMEOUT, DISCONNECT
    """

    # Discovery
    DISCOVERY             = "discovery"                # device probes for a gateway (mDNS)
    GATEWAY_ADVERTISEMENT = "gateway_advertisement"    # gateway advertises its services

    # Pairing (ECDH — produces a confidential channel, NOT proof of identity)
    PAIRING_REQUEST  = "pairing_request"               # device sends ECDH public key
    PAIRING_RESPONSE = "pairing_response"              # gateway completes ECDH exchange

    # Enrollment (authenticates the device inside the paired channel)
    ENROLLMENT_REQUEST   = "enrollment_request"        # device presents identity material
    ENROLLMENT_CONFIRMED = "enrollment_confirmed"      # AS verifies & stores → ENROLLED

    # Registration (legacy coarse alias, kept for backward compatibility)
    REGISTRATION_REQUEST   = "registration_request"
    REGISTRATION_CONFIRMED = "registration_confirmed"

    # Authentication
    AUTHENTICATION_REQUEST = "authentication_request"
    CHALLENGE_SENT         = "challenge_sent"
    NONCE_RECEIVED         = "nonce_received"       # server logs device nonce
    RESPONSE_SENT          = "response_sent"         # device submits challenge response
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"

    # Token lifecycle
    TOKEN_ISSUED    = "token_issued"
    TOKEN_PRESENTED = "token_presented"
    TOKEN_VALIDATED = "token_validated"
    TOKEN_REJECTED  = "token_rejected"
    RENEWAL_REQUEST = "renewal_request"
    TOKEN_EXPIRED   = "token_expired"

    # Session & resource access
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    ACCESS_REQUEST = "access_request"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED  = "access_denied"

    # Control
    RETRY      = "retry"
    TIMEOUT    = "timeout"
    DISCONNECT = "disconnect"


# ══════════════════════════════════════════════════════════════════════════════
# AuthState — 23 states
# ══════════════════════════════════════════════════════════════════════════════

class AuthState(str, Enum):
    """
    Internal state of a device/session at any point in the flow.

    Two uses:
      - Validate that a given event is allowed from the current state
        (normal scenario gating in StateMachine.advance).
      - Inject anomalies by forcing a forbidden transition
        (StateMachine.force + get_anomaly_transition).

    Lifecycle ordering
    ──────────────────
    UNREGISTERED → DISCOVERED → PAIRING → PAIRED → ENROLLING → ENROLLED
    → AUTH_REQUESTED → … → SESSION_OPEN.  ENROLLED is the resting state a device
    returns to after a session closes (it stays enrolled and re-authenticates).
    REGISTERED is kept as a backward-compatible alias of ENROLLED.

    Coexistence note
    ────────────────
    simulator/core/device.py still uses DeviceState (a coarser lifecycle enum
    from Phase 0).
    """
    UNREGISTERED      = "unregistered"
    DISCOVERED        = "discovered"        # gateway located (post-discovery)
    PAIRING           = "pairing"           # ECDH handshake in progress
    PAIRED            = "paired"            # confidential channel established
    ENROLLING         = "enrolling"         # identity being verified by the AS
    ENROLLED          = "enrolled"          # identity recorded — resting state
    REGISTERED        = "registered"        # legacy alias of ENROLLED
    AUTH_REQUESTED    = "auth_requested"
    CHALLENGE_ISSUED  = "challenge_issued"
    RESPONSE_SENT     = "response_sent"
    AUTHENTICATED     = "authenticated"
    TOKEN_ISSUED      = "token_issued"
    TOKEN_PRESENTED   = "token_presented"
    TOKEN_VALIDATED   = "token_validated"
    SESSION_OPEN      = "session_open"
    ACCESS_REQUESTED  = "access_requested"
    ACCESS_GRANTED    = "access_granted"
    ACCESS_DENIED     = "access_denied"
    RENEWAL_REQUESTED = "renewal_requested"
    TOKEN_EXPIRED     = "token_expired"
    AUTH_FAILED       = "auth_failed"
    REVOKED           = "revoked"
    BLOCKED           = "blocked"


# ══════════════════════════════════════════════════════════════════════════════
# EventResult
# ══════════════════════════════════════════════════════════════════════════════

class EventResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"


# ══════════════════════════════════════════════════════════════════════════════
# AuthEvent — one event in a correlated sequence
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthEvent:
    """
    A single authentication event with full state, timing, and identity context.

    Mandatory fields
    ───────────────
    These form the minimum context needed to detect any of the 9 target anomalies.
    Every call site must supply them explicitly.

    Optional fields
    ───────────────
    Contextual fields relevant only to specific event types (nonce for
    NONCE_RECEIVED/RESPONSE_SENT) or to specific anomaly checks (token_expiry
    for abnormal renewal).  Defaulting to None keeps the schema stable across
    all event types.

    Anomaly relevance map
    ─────────────────────
    token_id + session_id + device_id   → identity / token / session consistency
    nonce                               → nonce reuse detection
    timestamp + delay_since_previous    → replay window, timestamp inconsistency
    result + failure_reason + retry_count → abnormal failure rate
    previous_state + new_state          → step-order anomalies
    topic + resource_id                 → minimal MQTT/IoT context
    token_expiry                        → abnormal renewal frequency
    identity_claim                      → device impersonation
    anomaly_label                       → ground truth for ML training
    """

    # ── Mandatory ─────────────────────────────────────────────────────────────
    event_type:     EventType
    device_id:      str
    gateway_id:     str
    auth_server_id: str
    previous_state: AuthState
    new_state:      AuthState
    result:         EventResult

    # ── Auto-generated identifiers ────────────────────────────────────────────
    event_id:    str   = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   float = field(default_factory=time.time)
    scenario_id: str   = field(default="")
    session_id:  str   = field(default="")

    # ── Identity & token ──────────────────────────────────────────────────────
    token_id:       Optional[str] = field(default=None)
    nonce:          Optional[str] = field(default=None)
    identity_claim: Optional[str] = field(default=None)  # claimed device_id (impersonation)

    # ── Failure context ───────────────────────────────────────────────────────
    failure_reason: Optional[str] = field(default=None)
    retry_count:    int           = field(default=0)

    # ── Temporal ──────────────────────────────────────────────────────────────
    # Seconds elapsed since the previous event in the same session/scenario.
    # Zero for the first event.  Key feature for replay and timestamp anomalies.
    delay_since_previous_event: float = field(default=0.0)

    # ── Token context ─────────────────────────────────────────────────────────
    token_expiry: Optional[float] = field(default=None)   # Unix timestamp
    token_scope:  Optional[str]   = field(default=None)

    # ── MQTT / IoT context ────────────────────────────
    # Only a minimal application context is kept — not a full broker simulation.
    broker_id:   Optional[str] = field(default=None)
    topic:       Optional[str] = field(default=None)   # topic / resource requested
    resource_id: Optional[str] = field(default=None)

    # ── Device metadata ───────────────────────────────────────────────────────
    firmware_version: Optional[str] = field(default=None)
    source_context:   Optional[str] = field(default=None)  # "normal" | attack name

    # ── Ground truth ──────────────────────────────────────────────────────────
    # None  → normal event
    # str   → one of the 11 anomaly labels:
    #   "replay_token"           | "nonce_reuse"
    #   "timestamp_inconsistency"| "access_without_auth"
    #   "abnormal_failure_rate"  | "impersonation"
    #   "identity_token_mismatch"| "abnormal_renewal"
    #   "duplicate_sequence"     | "connect_flood"
    #   "delayed_connect"
    anomaly_label: Optional[str] = field(default=None)

    # ══════════════════════════════════════════════════════════════════════════
    # Serialisation
    # ══════════════════════════════════════════════════════════════════════════

    def to_dict(self) -> dict:
        """
        Flat dict — used by output_views for JSON / CSV export.
        Enum values serialised to strings.  None values kept (not dropped) so
        the schema stays stable across all event types.
        """
        return {
            # Identifiers
            "event_id":                   self.event_id,
            "event_type":                 self.event_type.value,
            "timestamp":                  round(self.timestamp, 6),
            "scenario_id":                self.scenario_id,
            "session_id":                 self.session_id,
            # Entities
            "device_id":                  self.device_id,
            "gateway_id":                 self.gateway_id,
            "auth_server_id":             self.auth_server_id,
            "broker_id":                  self.broker_id,
            # State transition
            "previous_state":             self.previous_state.value,
            "new_state":                  self.new_state.value,
            # Result
            "result":                     self.result.value,
            "failure_reason":             self.failure_reason,
            "retry_count":                self.retry_count,
            # Token & identity
            "token_id":                   self.token_id,
            "token_expiry":               self.token_expiry,
            "token_scope":                self.token_scope,
            "nonce":                      self.nonce,
            "identity_claim":             self.identity_claim,
            # Temporal
            "delay_since_previous_event": round(self.delay_since_previous_event, 4),
            # MQTT / IoT context
            "topic":                      self.topic,
            "resource_id":                self.resource_id,
            # Metadata
            "firmware_version":           self.firmware_version,
            "source_context":             self.source_context,
            # Ground truth
            "anomaly_label":              self.anomaly_label,
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Convenience properties
    # ══════════════════════════════════════════════════════════════════════════

    @property
    def is_anomaly(self) -> bool:
        return self.anomaly_label is not None

    @property
    def is_token_event(self) -> bool:
        return self.event_type in {
            EventType.TOKEN_ISSUED,    EventType.TOKEN_PRESENTED,
            EventType.TOKEN_VALIDATED, EventType.TOKEN_REJECTED,
            EventType.RENEWAL_REQUEST, EventType.TOKEN_EXPIRED,
        }

    @property
    def is_failure(self) -> bool:
        return self.result == EventResult.FAILURE

    @property
    def state_changed(self) -> bool:
        return self.previous_state != self.new_state

    def __repr__(self) -> str:
        anomaly = f"  [{self.anomaly_label}]" if self.anomaly_label else ""
        return (
            f"AuthEvent({self.event_type.value}  "
            f"{self.previous_state.value} → {self.new_state.value}  "
            f"{self.result.value}{anomaly})"
        )