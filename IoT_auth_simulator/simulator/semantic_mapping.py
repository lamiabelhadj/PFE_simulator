"""C1.1 mapping between historical implementation terms and v1 concepts.

The keys in this module are the exact vocabulary inherited from 27135bf.  The
descriptive ``semantic_concept`` values are implementation-facing concepts from
the Behavioral-model-v1 contract, not a final canonical vocabulary.  Canonical
state, event, and invariant identifiers remain unset because the authoritative
contracts deliberately leave them open.

This module is descriptive scaffolding only: the state machine, event engine,
anomaly injection, schemas, and output behavior do not import or execute it.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Mapping, Optional

from simulator.core.device import DeviceState
from simulator.event_model import AuthState, EventType
from simulator.provenance import (
    BEHAVIOR_MODEL_VERSION,
    EVENT_SCHEMA_VERSION,
    FEATURE_SCHEMA_VERSION,
    GENERATOR_SOFTWARE_VERSION,
)


class MappingStatus(str, Enum):
    MAPPED = "mapped"
    LEGACY_ALIAS = "legacy alias"
    COMPOSITE = "composite"
    IMPLEMENTATION_ONLY = "implementation-only"
    UNRESOLVED = "unresolved"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class MappingEntry:
    implementation_name: str
    status: MappingStatus
    semantic_concept: Optional[str]
    semantic_identifier: Optional[str] = None
    semantic_dimension: Optional[str] = None
    implementation_alignment: Optional[str] = None
    required_direction: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        return data


def _entry(
    name: str,
    status: MappingStatus,
    concept: Optional[str],
    *,
    dimension: Optional[str] = None,
    alignment: Optional[str] = None,
    direction: Optional[str] = None,
    notes: str = "",
) -> MappingEntry:
    return MappingEntry(
        implementation_name=name,
        status=status,
        semantic_concept=concept,
        semantic_identifier=None,
        semantic_dimension=dimension,
        implementation_alignment=alignment,
        required_direction=direction,
        notes=notes,
    )


# An entry being "mapped" means only that its historical name has a clear v1
# concept.  It does not make the name canonical or certify its current behavior.
EVENT_TYPE_MAPPINGS: Mapping[EventType, MappingEntry] = {
    EventType.DISCOVERY: _entry("discovery", MappingStatus.MAPPED, "device discovery/bootstrap observation"),
    EventType.GATEWAY_ADVERTISEMENT: _entry("gateway_advertisement", MappingStatus.MAPPED, "trusted gateway discovery response", notes="Reference-profile event."),
    EventType.PAIRING_REQUEST: _entry("pairing_request", MappingStatus.MAPPED, "pairing/bootstrap request"),
    EventType.PAIRING_RESPONSE: _entry("pairing_response", MappingStatus.MAPPED, "pairing/bootstrap response"),
    EventType.ENROLLMENT_REQUEST: _entry("enrollment_request", MappingStatus.MAPPED, "device enrollment request"),
    EventType.ENROLLMENT_CONFIRMED: _entry("enrollment_confirmed", MappingStatus.MAPPED, "enrolled condition established"),
    EventType.REGISTRATION_REQUEST: _entry("registration_request", MappingStatus.LEGACY_ALIAS, "enrollment request/condition", direction="Map or deprecate registration terminology; do not create a separate lifecycle stage."),
    EventType.REGISTRATION_CONFIRMED: _entry("registration_confirmed", MappingStatus.LEGACY_ALIAS, "enrolled condition established", direction="Map or deprecate registration terminology; do not create a separate lifecycle stage."),
    EventType.AUTHENTICATION_REQUEST: _entry("authentication_request", MappingStatus.MAPPED, "authentication attempt initiation"),
    EventType.CHALLENGE_SENT: _entry("challenge_sent", MappingStatus.MAPPED, "authentication challenge issuance"),
    EventType.NONCE_RECEIVED: _entry("nonce_received", MappingStatus.MAPPED, "challenge/nonce evidence observed", notes="The name remains implementation vocabulary; nonce role and uniqueness domain are profile-scoped."),
    EventType.RESPONSE_SENT: _entry("response_sent", MappingStatus.MAPPED, "authentication proof/response submission"),
    EventType.AUTHENTICATION_SUCCESS: _entry("authentication_success", MappingStatus.MAPPED, "successful authentication result"),
    EventType.AUTHENTICATION_FAILURE: _entry("authentication_failure", MappingStatus.MAPPED, "failed authentication result"),
    EventType.TOKEN_ISSUED: _entry("token_issued", MappingStatus.MAPPED, "credential/token establishment"),
    EventType.TOKEN_PRESENTED: _entry("token_presented", MappingStatus.MAPPED, "credential/token presentation"),
    EventType.TOKEN_VALIDATED: _entry("token_validated", MappingStatus.MAPPED, "credential/token validation result"),
    EventType.TOKEN_REJECTED: _entry("token_rejected", MappingStatus.MAPPED, "credential/token rejection result"),
    EventType.RENEWAL_REQUEST: _entry("renewal_request", MappingStatus.MAPPED, "renewal/re-authentication initiation", notes="The universal re-authentication/re-authorization relationship remains unresolved."),
    EventType.TOKEN_EXPIRED: _entry("token_expired", MappingStatus.MAPPED, "credential validity/freshness expiry"),
    EventType.SESSION_OPENED: _entry("session_opened", MappingStatus.MAPPED, "protected session establishment"),
    EventType.SESSION_CLOSED: _entry("session_closed", MappingStatus.MAPPED, "protected session termination"),
    EventType.ACCESS_REQUEST: _entry("access_request", MappingStatus.MAPPED, "protected resource operation request"),
    EventType.ACCESS_GRANTED: _entry("access_granted", MappingStatus.COMPOSITE, "authorization grant and/or successful protected operation", alignment="conflicting", direction="Separate authorization decision evidence from resulting protected access where applicable."),
    EventType.ACCESS_DENIED: _entry("access_denied", MappingStatus.COMPOSITE, "authorization denial and/or denied protected operation", alignment="partial", direction="Keep the authorization decision distinct from resource access outcome."),
    EventType.RETRY: _entry("retry", MappingStatus.MAPPED, "retry/recovery action"),
    EventType.TIMEOUT: _entry("timeout", MappingStatus.MAPPED, "authentication/session timeout"),
    EventType.DISCONNECT: _entry("disconnect", MappingStatus.MAPPED, "protected session disconnection"),
}


AUTH_STATE_MAPPINGS: Mapping[AuthState, MappingEntry] = {
    AuthState.UNREGISTERED: _entry("unregistered", MappingStatus.MAPPED, "not enrolled", dimension="persistent-device/enrollment", notes="Its placement in AuthState does not make it session-local."),
    AuthState.DISCOVERED: _entry("discovered", MappingStatus.MAPPED, "device known/discovered", dimension="persistent-device/enrollment"),
    AuthState.PAIRING: _entry("pairing", MappingStatus.MAPPED, "pairing/bootstrap in progress", dimension="persistent-device/enrollment"),
    AuthState.PAIRED: _entry("paired", MappingStatus.MAPPED, "pairing/bootstrap established", dimension="persistent-device/enrollment"),
    AuthState.ENROLLING: _entry("enrolling", MappingStatus.MAPPED, "enrollment in progress", dimension="persistent-device/enrollment"),
    AuthState.ENROLLED: _entry("enrolled", MappingStatus.MAPPED, "enrolled condition", dimension="persistent-device/enrollment"),
    AuthState.REGISTERED: _entry("registered", MappingStatus.LEGACY_ALIAS, "enrolled condition", dimension="persistent-device/enrollment", alignment="superseded implementation residue", direction="Treat exactly as the enrolled condition for v1 mapping; remove only through controlled migration."),
    AuthState.AUTH_REQUESTED: _entry("auth_requested", MappingStatus.MAPPED, "authentication attempt initiated", dimension="authentication/session"),
    AuthState.CHALLENGE_ISSUED: _entry("challenge_issued", MappingStatus.MAPPED, "authentication challenge active", dimension="authentication/session"),
    AuthState.RESPONSE_SENT: _entry("response_sent", MappingStatus.MAPPED, "authentication response submitted", dimension="authentication/session"),
    AuthState.AUTHENTICATED: _entry("authenticated", MappingStatus.MAPPED, "authenticated context", dimension="authentication/session"),
    AuthState.TOKEN_ISSUED: _entry("token_issued", MappingStatus.MAPPED, "issued credential/token context", dimension="authentication/session"),
    AuthState.TOKEN_PRESENTED: _entry("token_presented", MappingStatus.MAPPED, "presented credential/token context", dimension="authentication/session"),
    AuthState.TOKEN_VALIDATED: _entry("token_validated", MappingStatus.MAPPED, "validated credential/token context", dimension="authentication/session"),
    AuthState.SESSION_OPEN: _entry("session_open", MappingStatus.MAPPED, "active protected session", dimension="authentication/session"),
    AuthState.ACCESS_REQUESTED: _entry("access_requested", MappingStatus.MAPPED, "protected operation awaiting decision/outcome", dimension="authentication/session"),
    AuthState.ACCESS_GRANTED: _entry("access_granted", MappingStatus.COMPOSITE, "authorization grant and/or successful protected operation context", dimension="authentication/session", alignment="conflicting"),
    AuthState.ACCESS_DENIED: _entry("access_denied", MappingStatus.COMPOSITE, "authorization denial and/or denied operation context", dimension="authentication/session", alignment="partial"),
    AuthState.RENEWAL_REQUESTED: _entry("renewal_requested", MappingStatus.MAPPED, "renewal/re-authentication in progress", dimension="authentication/session"),
    AuthState.TOKEN_EXPIRED: _entry("token_expired", MappingStatus.MAPPED, "credential no longer valid by time", dimension="authentication/session"),
    AuthState.AUTH_FAILED: _entry("auth_failed", MappingStatus.MAPPED, "failed authentication attempt", dimension="authentication/session"),
    AuthState.REVOKED: _entry("revoked", MappingStatus.MAPPED, "revoked device/credential condition", dimension="persistent-device/enrollment", notes="The exact revocation object remains profile-dependent."),
    AuthState.BLOCKED: _entry("blocked", MappingStatus.MAPPED, "blocked/policy condition", dimension="persistent-device/enrollment", notes="This state alone is not evidence of abnormal failure frequency."),
}


DEVICE_STATE_MAPPINGS: Mapping[DeviceState, MappingEntry] = {
    DeviceState.IDLE: _entry("IDLE", MappingStatus.IMPLEMENTATION_ONLY, "wired-entity execution idle", dimension="implementation-control"),
    DeviceState.DISCOVERING: _entry("DISCOVERING", MappingStatus.MAPPED, "device discovery/bootstrap in progress", dimension="persistent-device/enrollment"),
    DeviceState.PAIRING: _entry("PAIRING", MappingStatus.MAPPED, "pairing/bootstrap in progress", dimension="persistent-device/enrollment"),
    DeviceState.ENROLLING: _entry("ENROLLING", MappingStatus.MAPPED, "enrollment in progress", dimension="persistent-device/enrollment"),
    DeviceState.AUTHORIZING: _entry("AUTHORIZING", MappingStatus.COMPOSITE, "authentication/token/authorization processing", dimension="authentication/session", alignment="conflicting", direction="Do not use this coarse state to collapse distinct security decisions."),
    DeviceState.SESSION_OPEN: _entry("SESSION_OPEN", MappingStatus.COMPOSITE, "active protected session plus wired execution phase", dimension="authentication/session", alignment="partial"),
    DeviceState.REAUTHENTICATING: _entry("REAUTHENTICATING", MappingStatus.MAPPED, "renewal/re-authentication in progress", dimension="authentication/session"),
    DeviceState.COMPLETED: _entry("COMPLETED", MappingStatus.IMPLEMENTATION_ONLY, "wired-entity execution completed", dimension="implementation-control"),
    DeviceState.FAILED: _entry("FAILED", MappingStatus.COMPOSITE, "unspecified wired-entity operation failure", dimension="implementation-control", notes="Failure is not itself anomaly truth."),
    DeviceState.ATTACKING: _entry("ATTACKING", MappingStatus.IMPLEMENTATION_ONLY, "attack scenario intent", dimension="scenario-metadata", alignment="conflicting", notes="Attack intent does not establish an observable anomaly."),
}


ANOMALY_NAME_MAPPINGS: Mapping[str, MappingEntry] = {
    "replay_token": _entry("replay_token", MappingStatus.MAPPED, "replay/single-use and credential/token-binding violation", alignment="conflicting", direction="Repair to require identifiable reuse of prior token material in a forbidden context."),
    "nonce_reuse": _entry("nonce_reuse", MappingStatus.MAPPED, "temporal/freshness and replay/single-use violation", alignment="partial", direction="Require actual prior occurrence and declared uniqueness-domain evidence."),
    "timestamp_inconsistency": _entry("timestamp_inconsistency", MappingStatus.MAPPED, "temporal/freshness consistency violation", alignment="partial", direction="Record and validate the violated temporal relationship; offsets are parameters only."),
    "duplicate_sequence": _entry("duplicate_sequence", MappingStatus.UNSUPPORTED, "lifecycle/causal ordering or replay/sequence uniqueness violation", alignment="conflicting", direction="Quarantine until actual duplicated sequence evidence exists; otherwise map an illegal event to transition validity."),
    "impersonation": _entry("impersonation", MappingStatus.COMPOSITE, "identity consistency, credential binding, and/or authentication-validity violations", alignment="conflicting", direction="Retain only as scenario provenance and expose each observable violation separately."),
    "identity_token_mismatch": _entry("identity_token_mismatch", MappingStatus.COMPOSITE, "identity consistency and/or credential/token-binding violation", alignment="conflicting", direction="Separate identity inconsistency from token-binding mismatch."),
    "access_without_auth": _entry("access_without_auth", MappingStatus.COMPOSITE, "authorization/access-precondition violation", alignment="conflicting", direction="Identify the specific authentication, token-validation, or authorization prerequisite violated."),
    "abnormal_failure_rate": _entry("abnormal_failure_rate", MappingStatus.UNSUPPORTED, "frequency/history behavior", alignment="conflicting", direction="Quarantine behavioral label until observable history/window and an approved limit or baseline exist."),
    "abnormal_renewal": _entry("abnormal_renewal", MappingStatus.COMPOSITE, "deterministic renewal validity and/or frequency/history behavior", alignment="conflicting", direction="Separate rule-decidable invalid renewal from statistically unusual renewal behavior."),
}


SCENARIO_MECHANISM_MAPPINGS: Mapping[str, MappingEntry] = {
    "normal": _entry("normal", MappingStatus.MAPPED, "invariant-compliant generated trace intent", notes="Observable validity must ultimately be validated, not inferred from this name."),
    "stealth_attack": _entry("stealth_attack", MappingStatus.IMPLEMENTATION_ONLY, "attack scenario intent with no injected observable violation", alignment="conflicting", direction="Treat invariant-compliant observations as normal/hard-negative, not positive anomaly ground truth."),
}


# Identifier roles introduced or clarified by C1.2.  ``session_id`` remains in
# historical outputs for compatibility and is explicitly prevented from
# defining any of the new semantic scopes.
IDENTIFIER_SEMANTICS = {
    "device_id": {
        "scope": "persistent device identity",
        "status": "mapped",
    },
    "trace_id": {
        "scope": "generated experimental trace/episode",
        "status": "mapped",
    },
    "scenario_id": {
        "scope": "scenario specification instance",
        "status": "mapped",
    },
    "auth_attempt_id": {
        "scope": "one authentication or re-authentication attempt",
        "status": "mapped",
    },
    "protected_session_id": {
        "scope": "one protected/operational session",
        "status": "mapped",
    },
    "session_id": {
        "scope": "historical per-trace grouping identifier",
        "status": "legacy alias",
        "must_not_define": [
            "device lifetime",
            "enrollment lifetime",
            "authentication attempt",
            "scenario identity",
            "trace identity",
            "protected-session identity",
        ],
    },
}


IMPLEMENTATION_FACTS = {
    "audit_baseline": "27135bf",
    "working_base": "54175c1",
    "auth_state_count": len(AuthState),
    "device_state_count": len(DeviceState),
    "event_type_count": len(EventType),
    # Imported lazily by report construction to keep the mapping independent of
    # state-machine execution and avoid presenting this count as semantic truth.
    "vocabulary_authority": "historical implementation facts only",
}


UNRESOLVED_SEMANTIC_QUESTIONS = (
    "Final semantic state vocabulary.",
    "Final semantic event vocabulary and canonical identifiers.",
    "Final invariant/anomaly catalogue and identifiers.",
    "Universal re-authentication and re-authorization relationship.",
    "Exact Resource Server and MQTT broker mapping beyond the v1 abstraction.",
    "Final replay/nonce/sequence uniqueness domains beyond explicitly declared profiles.",
)


def _serialized(mapping: Mapping) -> list[dict]:
    return [mapping[key].to_dict() for key in mapping]


def _status_counts(mapping: Mapping) -> dict[str, int]:
    return {
        status.value: sum(entry.status is status for entry in mapping.values())
        for status in MappingStatus
    }


def semantic_mapping_report() -> dict:
    """Return the complete C1.1 mapping as a machine-readable dictionary."""
    from simulator.state_machine import TRANSITIONS

    facts = dict(IMPLEMENTATION_FACTS)
    facts["transition_count"] = len(TRANSITIONS)
    return {
        "mapping_contract": "C1.1 implementation traceability scaffolding",
        "behavior_model_version": BEHAVIOR_MODEL_VERSION,
        "generator_software_version": GENERATOR_SOFTWARE_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "canonical_identifiers_assigned": False,
        "implementation_facts": facts,
        "event_types": _serialized(EVENT_TYPE_MAPPINGS),
        "auth_states": _serialized(AUTH_STATE_MAPPINGS),
        "device_states": _serialized(DEVICE_STATE_MAPPINGS),
        "anomaly_names": _serialized(ANOMALY_NAME_MAPPINGS),
        "scenario_mechanisms": _serialized(SCENARIO_MECHANISM_MAPPINGS),
        "identifier_semantics": IDENTIFIER_SEMANTICS,
        "status_summary": {
            "event_types": _status_counts(EVENT_TYPE_MAPPINGS),
            "auth_states": _status_counts(AUTH_STATE_MAPPINGS),
            "device_states": _status_counts(DEVICE_STATE_MAPPINGS),
            "anomaly_names": _status_counts(ANOMALY_NAME_MAPPINGS),
            "scenario_mechanisms": _status_counts(SCENARIO_MECHANISM_MAPPINGS),
        },
        "unresolved_semantic_questions": list(UNRESOLVED_SEMANTIC_QUESTIONS),
    }


def main() -> None:
    """Print the mapping report as stable, inspectable JSON."""
    print(json.dumps(semantic_mapping_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
