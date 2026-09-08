"""Explicit persistence scopes for Behavioral-model-v1 synchronized execution.

The dataclasses in this module separate device-lifetime enrollment facts from
the current authentication/protected-session interaction.  Historical
``AuthState`` values remain adapters for the existing state machine; they are
not promoted to canonical Behavioral-model-v1 state names.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from simulator.event_model import AuthState, EventResult, EventType


@dataclass
class PersistentDeviceContext:
    """Device-scoped security facts that survive trace/session termination."""

    device_id: str
    bootstrap_credential_reference: Optional[str] = None
    device_profile_id: Optional[str] = None
    discovered: bool = False
    paired: bool = False
    enrolled: bool = False
    revoked: bool = False
    blocked: bool = False

    # Reserved reference buckets for later explicitly authorized history work.
    # C1.2 does not assign replay/nonce/frequency semantics or populate them.
    history_references: Dict[str, List[str]] = field(default_factory=dict)

    def legacy_auth_state(self) -> AuthState:
        """Adapt persistent facts to the existing FSM's initial state."""
        if self.revoked:
            return AuthState.REVOKED
        if self.blocked:
            return AuthState.BLOCKED
        if self.enrolled:
            return AuthState.ENROLLED
        if self.paired:
            return AuthState.PAIRED
        if self.discovered:
            return AuthState.DISCOVERED
        return AuthState.UNREGISTERED

    def record_successful_event(
        self,
        event_type: EventType,
        resulting_state: AuthState,
    ) -> None:
        """Retain only established onboarding facts from a successful event."""
        if event_type in {EventType.DISCOVERY, EventType.GATEWAY_ADVERTISEMENT}:
            self.discovered = True
        elif event_type == EventType.PAIRING_RESPONSE:
            self.discovered = True
            self.paired = True
        elif event_type in {
            EventType.ENROLLMENT_CONFIRMED,
            EventType.REGISTRATION_REQUEST,
            EventType.REGISTRATION_CONFIRMED,
        } or resulting_state == AuthState.REGISTERED:
            # REGISTERED is historical residue and establishes only ENROLLED.
            self.discovered = True
            self.paired = True
            self.enrolled = True


@dataclass
class AuthenticationSessionContext:
    """Trace-local authentication, token, and protected-session relationships."""

    device_id: str
    trace_id: str
    scenario_id: str
    legacy_session_id: str
    current_auth_state: AuthState
    current_timestamp: float
    token_scope: str
    topic: str
    resource_id: str

    current_auth_attempt_id: Optional[str] = None
    auth_attempt_ids: List[str] = field(default_factory=list)
    renewal_auth_attempt_ids: List[str] = field(default_factory=list)
    current_challenge_nonce: Optional[str] = None
    token_id: Optional[str] = None
    token_expiry: Optional[float] = None
    protected_session_id: Optional[str] = None
    refreshes_protected_session_id: Optional[str] = None
    protected_session_active: bool = False
    authentication_attempt_active: bool = False
    renewal_in_progress: bool = False
    retry_count: int = 0
    last_result: Optional[EventResult] = None
    last_failure_reason: Optional[str] = None
    terminated: bool = False

    def start_auth_attempt(self, *, renewal: bool = False) -> str:
        attempt_id = str(uuid.uuid4())
        self.current_auth_attempt_id = attempt_id
        self.auth_attempt_ids.append(attempt_id)
        self.authentication_attempt_active = True
        self.terminated = False
        self.renewal_in_progress = renewal
        if renewal:
            self.renewal_auth_attempt_ids.append(attempt_id)
            self.refreshes_protected_session_id = self.protected_session_id
        return attempt_id

    def open_protected_session(self) -> str:
        if self.protected_session_id is None:
            self.protected_session_id = str(uuid.uuid4())
        self.protected_session_active = True
        self.terminated = False
        return self.protected_session_id

    def terminate_session(self) -> None:
        """End local activity without modifying persistent device context."""
        self.protected_session_active = False
        self.authentication_attempt_active = False
        self.renewal_in_progress = False
        self.terminated = True

    def record_result(
        self,
        result: EventResult,
        failure_reason: Optional[str],
    ) -> None:
        self.last_result = result
        self.last_failure_reason = failure_reason

    def finish_auth_attempt(self) -> None:
        self.authentication_attempt_active = False
        self.renewal_in_progress = False
