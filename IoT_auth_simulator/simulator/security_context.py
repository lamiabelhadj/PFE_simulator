"""Explicit persistence scopes for Behavioral-model-v1 synchronized execution.

The dataclasses in this module separate device-lifetime enrollment facts from
the current authentication/protected-session interaction.  Historical
``AuthState`` values remain adapters for the existing state machine; they are
not promoted to canonical Behavioral-model-v1 state names.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from simulator.anomaly_contract import InjectionRecord
from simulator.event_model import AuthState, EventResult, EventType


class AuthenticationResult(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    SUCCESS = "success"
    FAILURE = "failure"


class TokenValidationResult(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    VALIDATED = "validated"
    REJECTED = "rejected"


class AuthorizationDecision(str, Enum):
    NOT_EVALUATED = "not_evaluated"
    GRANTED = "granted"
    DENIED = "denied"


class ResourceOperationOutcome(str, Enum):
    NOT_EXECUTED = "not_executed"
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


@dataclass
class AccessRequestContext:
    """One protected-resource request and its distinct security decisions."""

    request_id: str
    device_id: str
    authenticated_identity: Optional[str]
    token_id: Optional[str]
    token_validation_result: TokenValidationResult
    protected_session_id: Optional[str]
    resource_id: str
    requested_action: str
    authorization_decision: AuthorizationDecision = AuthorizationDecision.NOT_EVALUATED
    resource_operation_outcome: ResourceOperationOutcome = ResourceOperationOutcome.NOT_EXECUTED
    decision_reason: Optional[str] = None


class ReferenceAuthorizationPolicy:
    """Minimum deterministic authorization policy for synchronized evidence.

    This is the default synthetic path's sole decision source.  It is a scoped
    reference policy, not a universal authorization model and not an assertion
    that the optional wired gateway is authoritative.
    """

    @staticmethod
    def evaluate(
        security_context: "AuthenticationSessionContext",
        request: AccessRequestContext,
    ) -> tuple[AuthorizationDecision, str]:
        if not security_context.protected_session_active:
            return AuthorizationDecision.DENIED, "no_active_protected_session"
        if security_context.authentication_result is not AuthenticationResult.SUCCESS:
            return AuthorizationDecision.DENIED, "no_successful_authentication"
        if not security_context.authenticated_context_active:
            return AuthorizationDecision.DENIED, "inactive_authenticated_context"
        if security_context.authenticated_identity != request.device_id:
            return AuthorizationDecision.DENIED, "authenticated_identity_mismatch"
        if request.authenticated_identity != security_context.authenticated_identity:
            return AuthorizationDecision.DENIED, "request_authentication_context_mismatch"
        if security_context.token_validation_result is not TokenValidationResult.VALIDATED:
            return AuthorizationDecision.DENIED, "token_not_validated"
        if not security_context.token_context_active:
            return AuthorizationDecision.DENIED, "inactive_token_context"
        if request.token_validation_result is not TokenValidationResult.VALIDATED:
            return AuthorizationDecision.DENIED, "request_token_not_validated"
        if not security_context.token_id or security_context.token_id != request.token_id:
            return AuthorizationDecision.DENIED, "token_context_mismatch"
        if request.protected_session_id != security_context.protected_session_id:
            return AuthorizationDecision.DENIED, "protected_session_context_mismatch"

        expected_prefix = f"resource://{request.device_id[:8]}/"
        if not request.resource_id.startswith(expected_prefix):
            return AuthorizationDecision.DENIED, "resource_identity_mismatch"

        try:
            scope_resource, permission = security_context.token_scope.split(":", 1)
        except ValueError:
            return AuthorizationDecision.DENIED, "malformed_token_scope"
        requested_resource = request.resource_id[len(expected_prefix):].split("/", 1)[0]
        if requested_resource != scope_resource:
            return AuthorizationDecision.DENIED, "resource_outside_token_scope"
        if permission != "readwrite" and request.requested_action != permission:
            return AuthorizationDecision.DENIED, "action_outside_token_scope"
        return AuthorizationDecision.GRANTED, "reference_policy_grant"


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
    semantic_time_cursor: Optional[float] = None
    completed_trace_count: int = 0

    def begin_trace(self, requested_start: float) -> float:
        """Return a start in this device's monotonic semantic history."""
        requested_start = float(requested_start)
        if self.semantic_time_cursor is None:
            return requested_start
        return max(requested_start, self.semantic_time_cursor)

    def complete_trace(self, semantic_end: float) -> None:
        """Commit chronological progress without assigning replay semantics."""
        semantic_end = float(semantic_end)
        if (
            self.semantic_time_cursor is not None
            and semantic_end < self.semantic_time_cursor
        ):
            raise ValueError("persistent device semantic time cannot move backwards")
        self.semantic_time_cursor = semantic_end
        self.completed_trace_count += 1

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
    requested_action: str
    semantic_time_domain: str = "synthetic-sequential-seconds"
    trace_started_at: Optional[float] = None
    trace_ended_at: Optional[float] = None

    current_auth_attempt_id: Optional[str] = None
    auth_attempt_ids: List[str] = field(default_factory=list)
    renewal_auth_attempt_ids: List[str] = field(default_factory=list)
    current_challenge_nonce: Optional[str] = None
    token_id: Optional[str] = None
    token_issued_at: Optional[float] = None
    token_presented_at: Optional[float] = None
    token_validation_at: Optional[float] = None
    token_validity_duration_s: Optional[float] = None
    token_expiry: Optional[float] = None
    protected_session_id: Optional[str] = None
    refreshes_protected_session_id: Optional[str] = None
    protected_session_active: bool = False
    authentication_attempt_active: bool = False
    renewal_in_progress: bool = False
    renewal_requested_at: Optional[float] = None
    renewed_token_issued_at: Optional[float] = None
    challenge_issued_at: Optional[float] = None
    challenge_response_at: Optional[float] = None
    protected_session_started_at: Optional[float] = None
    protected_session_ended_at: Optional[float] = None
    retry_count: int = 0
    last_result: Optional[EventResult] = None
    last_failure_reason: Optional[str] = None
    terminated: bool = False
    authentication_result: AuthenticationResult = AuthenticationResult.NOT_EVALUATED
    current_auth_attempt_result: AuthenticationResult = AuthenticationResult.NOT_EVALUATED
    authenticated_identity: Optional[str] = None
    authenticated_context_active: bool = False
    authentication_success_event_ids: List[str] = field(default_factory=list)
    token_issued: bool = False
    token_presented: bool = False
    token_validation_result: TokenValidationResult = TokenValidationResult.NOT_EVALUATED
    token_validation_event_id: Optional[str] = None
    token_context_active: bool = False
    current_access_request_id: Optional[str] = None
    access_request_ids: List[str] = field(default_factory=list)
    access_requests: Dict[str, AccessRequestContext] = field(default_factory=dict)
    injection_records: List[InjectionRecord] = field(default_factory=list)

    def start_auth_attempt(self, *, renewal: bool = False) -> str:
        attempt_id = str(uuid.uuid4())
        self.current_auth_attempt_id = attempt_id
        self.auth_attempt_ids.append(attempt_id)
        self.authentication_attempt_active = True
        self.current_auth_attempt_result = AuthenticationResult.NOT_EVALUATED
        self.terminated = False
        self.renewal_in_progress = renewal
        if renewal:
            self.renewal_auth_attempt_ids.append(attempt_id)
            self.refreshes_protected_session_id = self.protected_session_id
        return attempt_id

    def open_protected_session(self, now: float) -> str:
        if self.protected_session_id is None:
            self.protected_session_id = str(uuid.uuid4())
        self.protected_session_active = True
        self.protected_session_started_at = float(now)
        self.protected_session_ended_at = None
        self.terminated = False
        return self.protected_session_id

    def terminate_session(self, now: float) -> None:
        """End local activity without modifying persistent device context."""
        self.protected_session_active = False
        self.authentication_attempt_active = False
        self.authenticated_context_active = False
        self.token_context_active = False
        self.renewal_in_progress = False
        self.terminated = True
        if self.protected_session_started_at is not None:
            self.protected_session_ended_at = float(now)

    def record_result(
        self,
        result: EventResult,
        failure_reason: Optional[str],
    ) -> None:
        self.last_result = result
        self.last_failure_reason = failure_reason

    def record_authentication_success(self, event_id: str) -> None:
        self.authentication_result = AuthenticationResult.SUCCESS
        self.current_auth_attempt_result = AuthenticationResult.SUCCESS
        self.authenticated_identity = self.device_id
        self.authenticated_context_active = True
        self.authentication_success_event_ids.append(event_id)

    def record_authentication_failure(self) -> None:
        self.current_auth_attempt_result = AuthenticationResult.FAILURE
        # A failed renewal does not itself establish refreshed credentials, but
        # C1.3 does not decide whether it universally invalidates the preceding
        # authenticated context. Preserve that context for the scoped profile.
        if not self.renewal_in_progress:
            self.authentication_result = AuthenticationResult.FAILURE
            self.authenticated_identity = None
            self.authenticated_context_active = False

    def start_access_request(self) -> AccessRequestContext:
        request = AccessRequestContext(
            request_id=str(uuid.uuid4()),
            device_id=self.device_id,
            authenticated_identity=self.authenticated_identity,
            token_id=self.token_id,
            token_validation_result=self.token_validation_result,
            protected_session_id=self.protected_session_id,
            resource_id=self.resource_id,
            requested_action=self.requested_action,
        )
        self.current_access_request_id = request.request_id
        self.access_request_ids.append(request.request_id)
        self.access_requests[request.request_id] = request
        return request

    @property
    def current_access_request(self) -> Optional[AccessRequestContext]:
        if self.current_access_request_id is None:
            return None
        return self.access_requests.get(self.current_access_request_id)

    def record_access_decision(
        self,
        decision: AuthorizationDecision,
        outcome: ResourceOperationOutcome,
        reason: str,
    ) -> None:
        request = self.current_access_request
        if request is None:
            raise RuntimeError("authorization decision requires an access request")
        request.authorization_decision = decision
        request.resource_operation_outcome = outcome
        request.decision_reason = reason

    def finish_auth_attempt(self) -> None:
        self.authentication_attempt_active = False
        self.renewal_in_progress = False
