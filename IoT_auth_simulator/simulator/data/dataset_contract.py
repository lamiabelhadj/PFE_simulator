"""Machine-readable C1.6 dataset information-boundary contract.

This module classifies implementation fields; it does not decide which fields
04 will use in an experiment.  The synchronized detector view is deliberately
small.  Fields whose observability depends on a yet-undefined monitoring point
are kept outside it and described conservatively as debug or provenance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable, Optional

from simulator.anomaly_contract import synchronized_capability_report
from simulator.provenance import GenerationProvenance
from simulator.validation import (
    GROUND_TRUTH_SCHEMA_VERSION,
    VALIDATION_SCHEMA_VERSION,
    VALIDATOR_VERSION,
)


FIELD_MANIFEST_VERSION = "c1.7-development-field-manifest"
DATASET_MANIFEST_VERSION = "c1.7-development-dataset-manifest"
DATASET_INTERFACE_VERSION = "c1.7-development-dataset-interface"
SYNCHRONIZED_OBSERVATION_VIEW = "detector_observations"
HISTORICAL_FEATURE_VIEW = "historical_109_column_feature_representation"


class FieldRole(str, Enum):
    OBSERVABLE = "observable"
    DERIVED_OBSERVABLE = "derived_observable"
    GROUND_TRUTH = "ground_truth"
    DEBUG = "debug"
    PROVENANCE = "provenance"
    IDENTIFIER = "identifier"


class Availability(str, Enum):
    EVENT_TIME = "event_time"
    SESSION_FINAL = "session_final"
    RETROSPECTIVE = "retrospective"
    FUTURE_INFORMATION_DEPENDENT = "future_information_dependent"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class FieldDefinition:
    field_name: str
    export_view: str
    data_type: str
    role: FieldRole
    availability: Availability
    source: str
    derivation_description: Optional[str] = None
    source_fields: tuple[str, ...] = ()
    temporal_scope: Optional[str] = None
    uses_future_information: bool = False
    requires_session_completion: bool = False
    grouping_identifier: bool = False
    privileged: bool = False
    detector_feature_default: bool = False
    semantic_event_relationship: Optional[str] = None
    anomaly_invariant_relationship: Optional[str] = None
    implementation_notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["role"] = self.role.value
        result["availability"] = self.availability.value
        result["type"] = result.pop("data_type")
        return result


def _field(
    name: str,
    view: str,
    data_type: str,
    role: FieldRole,
    availability: Availability,
    source: str,
    **kwargs: Any,
) -> FieldDefinition:
    return FieldDefinition(
        field_name=name,
        export_view=view,
        data_type=data_type,
        role=role,
        availability=availability,
        source=source,
        **kwargs,
    )


_OBS = SYNCHRONIZED_OBSERVATION_VIEW
_GT_EVENT = "ground_truth_events"
_GT_TRACE = "ground_truth_traces"
_PROV_DATASET = "provenance_dataset"
_PROV_TRACE = "provenance_traces"
_PROV_EVENT = "provenance_events"
_DEBUG_EVENT = "debug_events"
_DEBUG_TRACE = "debug_traces"


# Inclusion here means role/horizon legitimacy only, never predictive utility.
SYNCHRONIZED_FIELD_DEFINITIONS: tuple[FieldDefinition, ...] = (
    _field("event_type", _OBS, "string", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.event_type", detector_feature_default=True,
           semantic_event_relationship="implemented event name; mapping remains noncanonical"),
    _field("observed_timestamp", _OBS, "number", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.observed_timestamp", detector_feature_default=True,
           implementation_notes="Detector receives observed time, never hidden semantic time."),
    _field("observed_delay_since_previous_event", _OBS, "number", FieldRole.DERIVED_OBSERVABLE,
           Availability.EVENT_TIME, "synchronized export transformation",
           derivation_description="Current observed timestamp minus the preceding observed timestamp in the trace.",
           source_fields=("observed_timestamp",), temporal_scope="trace_prefix",
           detector_feature_default=True),
    _field("result", _OBS, "string", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.result", detector_feature_default=True),
    _field("failure_reason", _OBS, "string|null", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.failure_reason", detector_feature_default=True),
    _field("retry_count", _OBS, "integer", FieldRole.DERIVED_OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.retry_count", derivation_description="Count available through the current trace prefix.",
           temporal_scope="trace_prefix", detector_feature_default=True),
    _field("token_id", _OBS, "string|null", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.token_id", detector_feature_default=True,
           anomaly_invariant_relationship="raw material only; no replay convenience flag"),
    _field("nonce", _OBS, "string|null", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.nonce", detector_feature_default=True,
           anomaly_invariant_relationship="raw challenge evidence only; no nonce_reused flag"),
    _field("topic", _OBS, "string|null", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.topic", detector_feature_default=True),
    _field("resource_id", _OBS, "string|null", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.resource_id", detector_feature_default=True),
    _field("requested_action", _OBS, "string|null", FieldRole.OBSERVABLE, Availability.EVENT_TIME,
           "AuthEvent.requested_action", detector_feature_default=True),

    _field("event_id", _GT_EVENT, "string", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "AuthEvent.event_id", privileged=True),
    _field("event_ordinal", _GT_EVENT, "integer", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "synchronized export ordering", privileged=True),
    _field("anomaly_label", _GT_EVENT, "string|null", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "AuthEvent.anomaly_label", privileged=True,
           implementation_notes="Candidate label reconciled with independent C1.7 validation status."),
    _field("anomaly_variant_name", _GT_EVENT, "string|null", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "AuthEvent.anomaly_variant_name", privileged=True),
    _field("invariant_families", _GT_EVENT, "array[string]", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "AuthEvent.invariant_families", privileged=True),
    _field("observable_violation_candidate", _GT_EVENT, "boolean", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "presence of C1.5 event candidate evidence", privileged=True),
    _field("validation_status", _GT_EVENT, "string", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "C1.7 independent validator", privileged=True),

    _field("trace_id", _GT_TRACE, "string", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "SessionContext.trace_id", grouping_identifier=True, privileged=True),
    _field("observable_anomaly", _GT_TRACE, "boolean", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "SessionContext.observable_anomaly", privileged=True,
           implementation_notes="C1.5 evidence outcome accompanied by independent C1.7 status."),
    _field("observable_violation_candidate", _GT_TRACE, "boolean", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "SessionContext.observable_violation_candidate", privileged=True),
    _field("anomaly_variants", _GT_TRACE, "array[string]", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "SessionContext.injection_records", privileged=True),
    _field("invariant_families", _GT_TRACE, "array[string]", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "SessionContext.injection_records", privileged=True),
    _field("validation_statuses", _GT_TRACE, "array[string]", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "SessionContext.injection_records", privileged=True),
    _field("hard_negative_status", _GT_TRACE, "string", FieldRole.GROUND_TRUTH,
           Availability.NOT_APPLICABLE, "dataset capability contract", privileged=True,
           implementation_notes="Not implemented; reserved without assigning a hard-negative label."),

    # Dataset-level provenance is serialized as one declared object.
    _field("generation", _PROV_DATASET, "object", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "GenerationProvenance", privileged=True),
    _field("capabilities", _PROV_DATASET, "object", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "dataset_capability_manifest", privileged=True),
    _field("field_manifest_version", _PROV_DATASET, "string", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "C1.7 integrated dataset contract", privileged=True),
    _field("row_alignment", _PROV_DATASET, "string", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "C1.6 information-boundary contract", privileged=True),
    _field("randomness_metadata", _PROV_DATASET, "object", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "generation configuration", privileged=True),

    _field("run_id", _PROV_TRACE, "string", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "GenerationProvenance.run_id", grouping_identifier=True, privileged=True),
    _field("trace_id", _PROV_TRACE, "string", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "SessionContext.trace_id", grouping_identifier=True, privileged=True),
    _field("scenario_id", _PROV_TRACE, "string", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "SessionContext.scenario_id", grouping_identifier=True, privileged=True),
    _field("device_id", _PROV_TRACE, "string", FieldRole.IDENTIFIER, Availability.NOT_APPLICABLE,
           "SessionContext.device_id", grouping_identifier=True, privileged=True),
    _field("legacy_session_id", _PROV_TRACE, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "SessionContext.legacy_session_id",
           grouping_identifier=True, privileged=True),
    _field("protected_session_id", _PROV_TRACE, "string|null", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "SessionContext.protected_session_id",
           grouping_identifier=True, privileged=True),
    _field("auth_attempt_ids", _PROV_TRACE, "array[string]", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "SessionContext.auth_attempt_ids",
           grouping_identifier=True, privileged=True),
    _field("generation_profile", _PROV_TRACE, "string", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "SessionContext.generation_profile", privileged=True),
    _field("scenario_family", _PROV_TRACE, "string", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "SessionContext.attack_type", privileged=True),
    _field("scenario_intent", _PROV_TRACE, "boolean", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "SessionContext.attack_scenario_intent", privileged=True),
    _field("attack_phase", _PROV_TRACE, "string", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "SessionContext.attack_phase", privileged=True),
    _field("generator_severity", _PROV_TRACE, "string", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "SessionContext.severity", privileged=True),
    _field("injection_records", _PROV_TRACE, "array[object]", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "SessionContext.injection_records", privileged=True,
           anomaly_invariant_relationship="complete C1.5 transformation and source-material lineage"),

    _field("observation_row", _PROV_EVENT, "integer", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "synchronized export ordering", privileged=True),
    _field("event_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.event_id", privileged=True),
    _field("trace_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.trace_id", grouping_identifier=True, privileged=True),
    _field("scenario_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.scenario_id", grouping_identifier=True, privileged=True),
    _field("device_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.device_id", grouping_identifier=True, privileged=True),
    _field("gateway_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.gateway_id", grouping_identifier=True, privileged=True),
    _field("auth_server_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.auth_server_id", grouping_identifier=True, privileged=True),
    _field("broker_id", _PROV_EVENT, "string|null", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.broker_id", grouping_identifier=True, privileged=True),
    _field("legacy_session_id", _PROV_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.session_id", grouping_identifier=True, privileged=True),
    _field("protected_session_id", _PROV_EVENT, "string|null", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.protected_session_id", grouping_identifier=True, privileged=True),
    _field("auth_attempt_id", _PROV_EVENT, "string|null", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.auth_attempt_id", grouping_identifier=True, privileged=True),
    _field("access_request_id", _PROV_EVENT, "string|null", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.access_request_id", grouping_identifier=True, privileged=True),
    _field("injection_id", _PROV_EVENT, "string|null", FieldRole.PROVENANCE,
           Availability.NOT_APPLICABLE, "AuthEvent.injection_id", privileged=True),

    _field("event_id", _DEBUG_EVENT, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "AuthEvent.event_id", privileged=True),
    _field("semantic_timestamp", _DEBUG_EVENT, "number", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.timestamp", privileged=True,
           implementation_notes="Authoritative generator/validation time; hidden from detector."),
    _field("observed_timestamp_source", _DEBUG_EVENT, "string", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.observed_timestamp_source", privileged=True),
    _field("targeted_temporal_relationship", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.targeted_temporal_relationship", privileged=True),
    _field("previous_state", _DEBUG_EVENT, "string", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.previous_state", privileged=True),
    _field("new_state", _DEBUG_EVENT, "string", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.new_state", privileged=True),
    _field("authenticated_identity", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.authenticated_identity", privileged=True,
           implementation_notes="Conservative: monitoring point unresolved."),
    _field("token_validation_result", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.token_validation_result", privileged=True,
           implementation_notes="Conservative: internal semantic decision evidence."),
    _field("authorization_decision", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.authorization_decision", privileged=True,
           implementation_notes="Conservative: monitoring point unresolved."),
    _field("resource_operation_outcome", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.resource_operation_outcome", privileged=True),
    _field("authenticated_context_active", _DEBUG_EVENT, "boolean", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.authenticated_context_active", privileged=True),
    _field("token_context_active", _DEBUG_EVENT, "boolean", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.token_context_active", privileged=True),
    _field("protected_session_active", _DEBUG_EVENT, "boolean", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.protected_session_active", privileged=True),
    _field("source_context", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.source_context", privileged=True),
    _field("token_expiry", _DEBUG_EVENT, "number|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.token_expiry", privileged=True,
           implementation_notes="Conservative until credential visibility is defined."),
    _field("token_scope", _DEBUG_EVENT, "string|null", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "AuthEvent.token_scope", privileged=True),

    _field("trace_id", _DEBUG_TRACE, "string", FieldRole.IDENTIFIER,
           Availability.NOT_APPLICABLE, "SessionContext.trace_id", privileged=True),
    _field("semantic_time_context", _DEBUG_TRACE, "object", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "SessionContext C1.4 fields", privileged=True),
    _field("security_decision_context", _DEBUG_TRACE, "object", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "SessionContext C1.3 fields", privileged=True),
    _field("experimental_scores", _DEBUG_TRACE, "object", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "historical SessionContext score helpers", privileged=True,
           implementation_notes="trust/deviation/gateway decisions are noncanonical."),
    _field("privileged_generator_flags", _DEBUG_TRACE, "object", FieldRole.DEBUG,
           Availability.NOT_APPLICABLE, "historical SessionContext anomaly helpers", privileged=True),
    _field("full_session_aggregates", _DEBUG_TRACE, "object", FieldRole.DEBUG,
           Availability.RETROSPECTIVE, "legacy feature builder", privileged=True,
           derivation_description="Aggregates require the complete event sequence.",
           source_fields=("events",), temporal_scope="complete_trace",
           uses_future_information=True, requires_session_completion=True),
)


def field_manifest() -> dict[str, Any]:
    return {
        "manifest_version": FIELD_MANIFEST_VERSION,
        "authority_boundary": {
            "classification_owner": "03",
            "experiment_selection_owner": "04",
            "canonical_behavior_owner": "02",
        },
        "role_vocabulary": [role.value for role in FieldRole],
        "availability_vocabulary": [item.value for item in Availability],
        "default_detector_view": _OBS,
        "default_detector_view_policy": (
            "Only observable and derived_observable fields marked "
            "detector_feature_default; no identifiers, GT, debug, or provenance."
        ),
        "fields": [item.to_dict() for item in SYNCHRONIZED_FIELD_DEFINITIONS],
        "legacy_representation": historical_feature_contract(),
    }


def fields_for_view(view: str) -> tuple[FieldDefinition, ...]:
    return tuple(item for item in SYNCHRONIZED_FIELD_DEFINITIONS if item.export_view == view)


def field_names_for_view(view: str) -> tuple[str, ...]:
    return tuple(item.field_name for item in fields_for_view(view))


def historical_feature_contract(columns: Optional[Iterable[str]] = None) -> dict[str, Any]:
    """Describe—not legitimize—the mixed historical session-feature table."""
    privileged_names = {
        "is_anomaly", "attack_type", "attack_phase", "severity",
        "attack_scenario_intent", "observable_anomaly",
        "observable_violation_candidate", "generation_profile", "injection_count",
        "token_age_at_replay", "nonce_age_at_reuse", "timestamp_delta_s",
        "duplicate_session_count", "identity_claim_mismatch",
        "token_device_mismatch", "unauthorized_access_attempt",
        "identity_mismatch", "n_token_reuses", "n_nonce_reuses", "n_state_jumps",
        "trust_score", "behavior_deviation_score", "gateway_decision",
        "replay_window_violation", "topic_scope_violation", "source_ip_change",
    }
    identifier_names = {
        "scenario_id", "trace_id", "session_id", "protected_session_id",
        "device_id", "gateway_id",
    }
    retrospective_prefixes = ("n_", "reached_", "visited_")
    migration = []
    for name in (() if columns is None else columns):
        if name in identifier_names:
            classification = FieldRole.IDENTIFIER.value
        elif name in privileged_names:
            classification = "legacy_privileged_or_shortcut"
        elif name.startswith(retrospective_prefixes) or name in {
            "session_duration_s", "mean_delay_s", "max_delay_s", "min_delay_s",
            "failure_rate", "auth_attempt_count", "access_request_count",
        }:
            classification = "legacy_retrospective"
        else:
            classification = "ambiguous_requires_03_observability_review"
        migration.append({"field_name": name, "provisional_disposition": classification})
    return {
        "view_name": HISTORICAL_FEATURE_VIEW,
        "status": "legacy_mixed_role_not_detector_ready",
        "canonical_schema": False,
        "detector_ready": False,
        "historical_column_count_is_not_a_requirement": True,
        "migration_metadata": migration,
    }


def dataset_capability_manifest(
    provenance: GenerationProvenance,
    *,
    generation_profiles: Iterable[str],
) -> dict[str, Any]:
    anomaly = synchronized_capability_report()
    profiles = sorted(set(generation_profiles))
    supported = sorted(anomaly["supported_variants"])
    all_non_supported = sorted(
        name for name, item in anomaly["variants"].items()
        if name not in supported
    )
    quarantined = sorted(
        name for name, item in anomaly["variants"].items()
        if item["status"] == "quarantined_historical_variant"
    )
    composite = sorted(
        name for name, item in anomaly["variants"].items()
        if item["status"] == "composite_scenario_provenance_only"
    )
    history_dependent = sorted(
        name for name, item in anomaly["variants"].items()
        if item["status"] == "unsupported_history_dependent_behavior"
    )
    return {
        "manifest_version": DATASET_MANIFEST_VERSION,
        "dataset_interface_version": DATASET_INTERFACE_VERSION,
        "dataset_version": "c1.7-development-unreleased",
        "behavior_model_version": provenance.behavior_model_version,
        "event_schema_version": provenance.event_schema_version,
        "feature_schema_version": provenance.feature_schema_version,
        "generator_software_version": provenance.generator_software_version,
        "generator_git_commit": provenance.generator_git_commit,
        "run_id": provenance.run_id,
        "generation_profile": profiles[0] if len(profiles) == 1 else "mixed",
        "generation_profiles": profiles,
        "supported_synchronized_anomaly_variants": supported,
        "quarantined_historical_variants": quarantined,
        "composite_scenario_provenance_only": composite,
        "unsupported_history_dependent_variants": history_dependent,
        "all_non_supported_historical_variants": all_non_supported,
        "persistent_device_context_support": "implemented",
        "cross_session_history_support": "device_timeline_only_no_replay_material_history",
        "hard_negative_capability": "not_implemented_as_dataset_truth",
        "global_discrete_event_simulation": False,
        "concurrency_support": "none_sequential_generation_only",
        "operational_trace_support": False,
        "calibration_status": "not_calibrated_against_operational_or_testbed_data",
        "validator_version": VALIDATOR_VERSION,
        "validation_schema_version": VALIDATION_SCHEMA_VERSION,
        "ground_truth_schema_version": GROUND_TRUTH_SCHEMA_VERSION,
        "full_executable_invariant_validation": "implemented_supported_v1_subset",
        "default_detector_view": _OBS,
        "known_limitations": [
            "Only the deterministic and two anomaly-evidence checks in the C1.7 supported subset are validated.",
            "Validation may reject traces produced by historical transient-progression behavior; failures are retained rather than relabeled.",
            "Monitoring/observation point is unresolved; internal security decisions are excluded.",
            "No cross-session token or nonce material history is claimed.",
            "No final ML prediction horizon or feature selection is encoded.",
            "Historical session feature representation remains mixed-role legacy evidence.",
        ],
    }
