"""C1.5 synchronized anomaly capability and injection provenance.

Names and invariant families here are implementation-facing contract mappings,
not newly assigned canonical identifiers or a final anomaly taxonomy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional, Tuple


SYNCHRONIZED_GENERATION_PROFILE = "c1-v1-synchronized"
HISTORICAL_GENERATION_PROFILE = "historical-27135bf"


class VariantCapabilityStatus(str, Enum):
    SUPPORTED_PENDING_VALIDATION = "supported_awaiting_final_executable_validation"
    QUARANTINED_HISTORICAL = "quarantined_historical_variant"
    COMPOSITE_SCENARIO_PROVENANCE = "composite_scenario_provenance_only"
    UNSUPPORTED_HISTORY_DEPENDENT = "unsupported_history_dependent_behavior"


@dataclass(frozen=True)
class VariantCapability:
    historical_name: str
    status: VariantCapabilityStatus
    semantic_concept: str
    invariant_families: Tuple[str, ...] = ()
    history_scope: Optional[str] = None
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        record["status"] = self.status.value
        record["canonical_identifier"] = None
        return record


VARIANT_CAPABILITIES = {
    "nonce_reuse": VariantCapability(
        "nonce_reuse",
        VariantCapabilityStatus.SUPPORTED_PENDING_VALIDATION,
        "reuse of challenge nonce material across authentication attempts",
        ("temporal/freshness consistency", "replay/single-use"),
        "within_trace_across_authentication_attempts",
        "The v1 contract explicitly requires within-trace attempt history.",
    ),
    "timestamp_inconsistency": VariantCapability(
        "timestamp_inconsistency",
        VariantCapabilityStatus.SUPPORTED_PENDING_VALIDATION,
        "observed timestamp violates causal predecessor ordering",
        ("temporal/freshness consistency",),
        "within_trace_causal_predecessor",
        "Semantic time remains monotonic; only declared/observed evidence changes.",
    ),
    "replay_token": VariantCapability(
        "replay_token",
        VariantCapabilityStatus.QUARANTINED_HISTORICAL,
        "token replay/reuse",
        ("replay/single-use", "credential/token binding"),
        None,
        "No approved token reuse-forbidden domain exists; token age is insufficient.",
    ),
    "duplicate_sequence": VariantCapability(
        "duplicate_sequence",
        VariantCapabilityStatus.QUARANTINED_HISTORICAL,
        "sequence duplication",
        ("lifecycle/causal ordering", "replay/single-use"),
        None,
        "Historical injection does not duplicate a meaningful subsequence.",
    ),
    "impersonation": VariantCapability(
        "impersonation",
        VariantCapabilityStatus.COMPOSITE_SCENARIO_PROVENANCE,
        "identity/credential/authentication scenario bundle",
        ("identity consistency", "credential/token binding"),
        None,
        "Final decomposition requires authoritative identity taxonomy.",
    ),
    "identity_token_mismatch": VariantCapability(
        "identity_token_mismatch",
        VariantCapabilityStatus.COMPOSITE_SCENARIO_PROVENANCE,
        "identity and token-binding scenario bundle",
        ("identity consistency", "credential/token binding"),
        None,
        "The historical atomic label is not retained as synchronized truth.",
    ),
    "access_without_auth": VariantCapability(
        "access_without_auth",
        VariantCapabilityStatus.COMPOSITE_SCENARIO_PROVENANCE,
        "protected-access prerequisite scenario bundle",
        ("authorization/access preconditions",),
        None,
        "Exact violated prerequisite is not safely encoded by the historical path.",
    ),
    "abnormal_failure_rate": VariantCapability(
        "abnormal_failure_rate",
        VariantCapabilityStatus.UNSUPPORTED_HISTORY_DEPENDENT,
        "failure frequency/history behavior",
        ("frequency/history behavior",),
        None,
        "Requires an approved history window and policy/baseline.",
    ),
    "abnormal_renewal": VariantCapability(
        "abnormal_renewal",
        VariantCapabilityStatus.UNSUPPORTED_HISTORY_DEPENDENT,
        "behaviorally unusual renewal frequency/timing",
        ("frequency/history behavior",),
        None,
        "Deterministic renewal invalidity must later be separated from behavior.",
    ),
}


def supported_synchronized_variants() -> Tuple[str, ...]:
    return tuple(
        name
        for name, capability in VARIANT_CAPABILITIES.items()
        if capability.status is VariantCapabilityStatus.SUPPORTED_PENDING_VALIDATION
    )


def synchronized_capability_report() -> dict[str, Any]:
    return {
        "generation_profile": SYNCHRONIZED_GENERATION_PROFILE,
        "canonical_identifiers_assigned": False,
        "variants": {
            name: capability.to_dict()
            for name, capability in VARIANT_CAPABILITIES.items()
        },
        "supported_variants": list(supported_synchronized_variants()),
    }


@dataclass
class InjectionRecord:
    """Controlled transformation provenance; not final validated ground truth."""

    injection_id: str
    historical_scenario_name: str
    anomaly_variant_name: str
    capability_status: str
    mapped_semantic_concept: str
    invariant_families: Tuple[str, ...]
    canonical_invariant_ids: Tuple[str, ...] = ()
    targeted_event_type: Optional[str] = None
    targeted_action_or_context: Optional[str] = None
    source_evidence_event_ids: Tuple[str, ...] = ()
    source_material_identifier: Optional[str] = None
    source_trace_id: Optional[str] = None
    source_session_id: Optional[str] = None
    source_auth_attempt_id: Optional[str] = None
    original_value: Any = None
    injected_value: Any = None
    injection_parameters: dict[str, Any] = field(default_factory=dict)
    trace_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    auth_attempt_id: Optional[str] = None
    declared_history_scope: Optional[str] = None
    intended_observable_violation: Optional[str] = None
    transformation_applied: bool = False
    evidence_check_passed: bool = False
    observable_violation_candidate: bool = False
    validation_status: str = "candidate_pending_full_executable_validation"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
