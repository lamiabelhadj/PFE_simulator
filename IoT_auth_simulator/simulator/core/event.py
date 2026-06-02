"""
simulator/core/event.py
───────────────────────
Lightweight event structure for tracking temporal and sequential behavior
in the authentication flows.

This module defines the AuthenticationEvent dataclass, which wraps each step
in the authentication flow with metadata including timestamps, state transitions,
and device/gateway/server identifiers. Events are collected during session execution
but do NOT appear in the flat CSV output (preserved for backward compatibility).

Events enable future extensions for:
  - Replay attack detection (duplicate events within a time window)
  - Timestamp anomalies (events arriving out of order or with abnormal delays)
  - Nonce/token reuse anomalies
  - State transition violations
  - 24-hour event window analysis
"""

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from enum import Enum


class EventType(Enum):
    """Enumeration of authentication flow event types."""
    DISCOVERY      = "discovery"
    PAIRING        = "pairing"
    ENROLLMENT     = "enrollment"
    AUTHORIZATION  = "authorization"
    MQTT_SESSION   = "mqtt_session"
    REAUTH         = "reauth"


@dataclass(frozen=True)
class AuthenticationEvent:
    """
    Immutable event record for a single step in the authentication flow.

    This structure captures:
      - Identity: event_id, scenario_id (session ID), event_type
      - Temporal: timestamp (Unix time in milliseconds)
      - Entity IDs: device, gateway, auth server, session, token
      - State: previous_state, new_state, result, failure_reason
      - Diagnostics: latency_ms, step_output (full feature dict)

    Events are collected during session execution and can later be:
      - Exported to a JSON event log
      - Used for temporal anomaly detection
      - Checked for replay/duplicate sequences
      - Analyzed for state transition violations
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    """Unique identifier for this event."""

    scenario_id: str = field(default="")
    """Links all events in the same session (same as session_id in flat row)."""

    event_type: str = field(default="")
    """Step name: 'discovery', 'pairing', 'enrollment', 'authorization', 'mqtt_session', 'reauth'."""

    # ── Temporal ──────────────────────────────────────────────────────────────
    timestamp_ms: float = field(default=0.0)
    """Unix timestamp in milliseconds when the event occurred."""

    # ── Entity IDs ────────────────────────────────────────────────────────────
    device_id: str = field(default="")
    """The device performing the authentication step."""

    gateway_id: str = field(default="")
    """The gateway processing the step."""

    auth_server_id: str = field(default="")
    """The authentication server involved ."""

    session_id: Optional[str] = field(default=None)
    """Session ID (set after enrollment step succeeds)."""

    token_id: Optional[str] = field(default=None)
    """Token ID or token hash (set after authorization step succeeds)."""

    # ── State Transition ──────────────────────────────────────────────────────
    previous_state: str = field(default="")
    """DeviceState before this step (e.g., 'IDLE', 'DISCOVERING')."""

    new_state: str = field(default="")
    """DeviceState after this step (e.g., 'PAIRING', 'DISCOVERING')."""

    # ── Result ────────────────────────────────────────────────────────────────
    result: bool = field(default=False)
    """True if step_success == 1 (step completed successfully)."""

    failure_reason: Optional[str] = field(default=None)
    """Reason for failure if result is False (e.g., 'enrollment_failed', 'invalid_token')."""

    retry_count: int = field(default=0)
    """Number of retries before this event (for future use with retry logic)."""

    # ── Diagnostics ───────────────────────────────────────────────────────────
    latency_ms: float = field(default=0.0)
    """Elapsed time for this step in milliseconds."""

    delay_since_previous_event_ms: float = field(default=0.0)
    """Time gap from previous event to this one (for anomaly detection)."""

    step_output: Dict[str, Any] = field(default_factory=dict)
    """Full feature dict returned by the step function (for debugging and analysis)."""

    # ── Anomaly Label (set by labeler, not during event creation) ─────────────
    is_anomaly: bool = field(default=False)
    """True if this event is part of an attack sequence."""

    attack_type: Optional[str] = field(default=None)
    """Attack type if is_anomaly is True ('replay', 'impersonation', 'dos_flooding')."""

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert event to a dictionary (useful for JSON export or debugging).

        Returns
        -------
        dict — all fields as a flat dictionary
        """
        return {
            "event_id": self.event_id,
            "scenario_id": self.scenario_id,
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "device_id": self.device_id,
            "gateway_id": self.gateway_id,
            "auth_server_id": self.auth_server_id,
            "session_id": self.session_id,
            "token_id": self.token_id,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "result": self.result,
            "failure_reason": self.failure_reason,
            "retry_count": self.retry_count,
            "latency_ms": self.latency_ms,
            "delay_since_previous_event_ms": self.delay_since_previous_event_ms,
            "is_anomaly": self.is_anomaly,
            "attack_type": self.attack_type,
        }

    def __repr__(self) -> str:
        return (
            f"Event(type={self.event_type}, device={self.device_id[:8]}…, "
            f"result={self.result}, latency_ms={self.latency_ms:.2f})"
        )
