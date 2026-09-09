"""Independent executable validation for the C1 synchronized v1 subset.

The validator inspects emitted events and contexts.  Scenario names and
injection records select an intended candidate check, but only reconstructed
event evidence can confirm a violation.  This is intentionally a focused rule
layer, not a second copy of the historical FSM or a final invariant catalogue.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

from simulator.anomaly_contract import (
    SYNCHRONIZED_GENERATION_PROFILE,
    supported_synchronized_variants,
)
from simulator.event_model import AuthEvent, AuthState, EventResult, EventType
from simulator.provenance import BEHAVIOR_MODEL_VERSION, GenerationProvenance


VALIDATOR_VERSION = "c1.7-development-validator"
VALIDATION_SCHEMA_VERSION = "c1.7-development-validation-report"
GROUND_TRUTH_SCHEMA_VERSION = "c1.7-development-ground-truth-schema"


class ValidationResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


class GroundTruthValidationStatus(str, Enum):
    VALIDATED_POSITIVE = "validated_positive"
    VALIDATED_NORMAL = "validated_normal"
    VALIDATION_FAILED = "validation_failed"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"


class BuildGateError(RuntimeError):
    """Raised when a caller elects to enforce a failed deterministic gate."""


class ValidationCategory(str, Enum):
    STATE_RESULT = "state_result_consistency"
    LIFECYCLE_CAUSAL = "lifecycle_causal_ordering"
    TEMPORAL = "temporal_consistency"
    IDENTITY = "identity_consistency"
    CREDENTIAL_TOKEN = "credential_token_binding"
    SESSION_CONTINUITY = "session_continuity_context"
    AUTHORIZATION_ACCESS = "authorization_access_preconditions"
    REPLAY_SINGLE_USE = "replay_single_use"
    TIMESTAMP_EVIDENCE = "timestamp_inconsistency_evidence"
    GROUND_TRUTH = "ground_truth_injection_consistency"
    SCHEMA_PROVENANCE = "schema_provenance_completeness"
    HARD_NEGATIVE = "hard_negative_candidate_validity"
    UNSUPPORTED_CAPABILITY = "unsupported_validation"


@dataclass(frozen=True)
class ValidationRecord:
    validation_id: str
    validation_category: ValidationCategory
    invariant_family: Optional[str]
    invariant_identifier: Optional[str]
    trace_id: Optional[str]
    device_id: Optional[str]
    protected_session_id: Optional[str]
    event_references: tuple[str, ...]
    expected_condition: str
    observed_evidence: dict[str, Any]
    result: ValidationResult
    reason: str
    validator_version: str = VALIDATOR_VERSION

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["validation_category"] = self.validation_category.value
        result["result"] = self.result.value
        return result


@dataclass
class ValidationReport:
    records: list[ValidationRecord]
    behavior_model_version: str
    generator_version: str
    generator_git_commit: Optional[str]
    event_schema_version: str
    feature_schema_version: str
    traces_checked: int
    events_checked: int
    trace_ground_truth_statuses: dict[str, str] = field(default_factory=dict)
    event_ground_truth_statuses: dict[str, str] = field(default_factory=dict)
    validated_positive_event_ids: set[str] = field(default_factory=set)
    unexpected_normal_trace_failures: list[str] = field(default_factory=list)
    intended_candidates_confirmed: list[dict[str, str]] = field(default_factory=list)
    intended_candidates_not_confirmed: list[dict[str, str]] = field(default_factory=list)
    gt_consistency_failures: list[str] = field(default_factory=list)
    provenance_schema_failures: list[str] = field(default_factory=list)
    build_gate_passed: bool = False
    mandatory_failure_reasons: list[str] = field(default_factory=list)

    def require_build_gate(self) -> None:
        """Provide an opt-in release gate without writing or deleting artifacts."""
        if not self.build_gate_passed:
            raise BuildGateError("; ".join(self.mandatory_failure_reasons))

    def to_dict(self) -> dict[str, Any]:
        result_counts = Counter(record.result.value for record in self.records)
        category_counts: dict[str, dict[str, int]] = {}
        for category in ValidationCategory:
            counts = Counter(
                record.result.value for record in self.records
                if record.validation_category is category
            )
            category_counts[category.value] = {
                status.value: counts.get(status.value, 0)
                for status in ValidationResult
            }
        return {
            "validation_schema_version": VALIDATION_SCHEMA_VERSION,
            "validator_version": VALIDATOR_VERSION,
            "behavior_model_version": self.behavior_model_version,
            "generator_version": self.generator_version,
            "generator_git_commit": self.generator_git_commit,
            "event_schema_version": self.event_schema_version,
            "feature_schema_version": self.feature_schema_version,
            "traces_checked": self.traces_checked,
            "events_checked": self.events_checked,
            "checks_executed_by_category": category_counts,
            "result_counts": {
                status.value: result_counts.get(status.value, 0)
                for status in ValidationResult
            },
            "unexpected_normal_trace_failures": self.unexpected_normal_trace_failures,
            "intended_anomaly_candidates_confirmed": self.intended_candidates_confirmed,
            "intended_anomaly_candidates_not_confirmed": self.intended_candidates_not_confirmed,
            "ground_truth_consistency_failures": self.gt_consistency_failures,
            "provenance_schema_failures": self.provenance_schema_failures,
            "ground_truth_status_vocabulary": [
                status.value for status in GroundTruthValidationStatus
            ],
            "trace_ground_truth_statuses": self.trace_ground_truth_statuses,
            "event_ground_truth_statuses": self.event_ground_truth_statuses,
            "validated_positive_event_ids": sorted(self.validated_positive_event_ids),
            "build_gate": {
                "passed": self.build_gate_passed,
                "mandatory_failure_reasons": self.mandatory_failure_reasons,
            },
            "records": [record.to_dict() for record in self.records],
        }


@dataclass
class _TraceOutcome:
    records: list[ValidationRecord]
    confirmed_event_ids: set[str]
    confirmed_variants: set[str]
    intended_variants: set[str]
    deterministic_failed: bool
    gt_failed: bool


class DatasetValidator:
    """Validate the deterministic subset represented by synchronized traces."""

    _DETERMINISTIC_CATEGORIES = {
        ValidationCategory.STATE_RESULT,
        ValidationCategory.LIFECYCLE_CAUSAL,
        ValidationCategory.TEMPORAL,
        ValidationCategory.IDENTITY,
        ValidationCategory.CREDENTIAL_TOKEN,
        ValidationCategory.SESSION_CONTINUITY,
        ValidationCategory.AUTHORIZATION_ACCESS,
    }

    def validate(
        self,
        sequences: list[tuple[list[AuthEvent], Any]],
        *,
        provenance: GenerationProvenance,
        field_manifest: Optional[dict[str, Any]],
        dataset_manifest: Optional[dict[str, Any]],
        hard_negative_trace_ids: Optional[Iterable[str]] = None,
    ) -> ValidationReport:
        records: list[ValidationRecord] = []
        outcomes: dict[str, _TraceOutcome] = {}
        internal_error_traces: list[str] = []

        for events, context in sequences:
            try:
                outcome = self._validate_trace(events, context)
            except Exception as exc:  # expose validator failure; never convert to pass
                record = self._record(
                    "c1.7.validator.internal_error",
                    ValidationCategory.STATE_RESULT,
                    context,
                    "mandatory trace validators execute without internal error",
                    {"exception_type": type(exc).__name__, "message": str(exc)},
                    ValidationResult.ERROR,
                    "validator execution failed",
                )
                outcome = _TraceOutcome([record], set(), set(), set(), True, True)
                internal_error_traces.append(context.trace_id)
            outcomes[context.trace_id] = outcome
            records.extend(outcome.records)

        persistence_record = self._validate_cross_trace_persistence(sequences)
        records.append(persistence_record)

        schema_record = self._validate_schema_provenance(
            sequences, provenance, field_manifest, dataset_manifest
        )
        records.append(schema_record)

        hard_negative_records = self._validate_hard_negative_candidates(
            sequences, outcomes, hard_negative_trace_ids
        )
        records.extend(hard_negative_records)
        records.extend(self._unsupported_records())

        unexpected_normal = sorted(
            context.trace_id
            for _events, context in sequences
            if not context.attack_scenario_intent
            and outcomes[context.trace_id].deterministic_failed
        )
        confirmed: list[dict[str, str]] = []
        not_confirmed: list[dict[str, str]] = []
        positive_event_ids: set[str] = set()
        gt_failures: list[str] = []
        trace_statuses: dict[str, str] = {}
        event_statuses: dict[str, str] = {}

        for events, context in sequences:
            outcome = outcomes[context.trace_id]
            positive_event_ids.update(outcome.confirmed_event_ids)
            for variant in sorted(outcome.intended_variants):
                item = {"trace_id": context.trace_id, "variant": variant}
                (confirmed if variant in outcome.confirmed_variants else not_confirmed).append(item)
            if outcome.gt_failed:
                gt_failures.append(context.trace_id)

            validation_failed = (
                outcome.deterministic_failed
                or outcome.gt_failed
                or outcome.intended_variants != outcome.confirmed_variants
            )
            if validation_failed:
                status = GroundTruthValidationStatus.VALIDATION_FAILED.value
            elif outcome.confirmed_variants:
                status = GroundTruthValidationStatus.VALIDATED_POSITIVE.value
            else:
                status = GroundTruthValidationStatus.VALIDATED_NORMAL.value
            trace_statuses[context.trace_id] = status
            for event in events:
                if status == "validation_failed":
                    event_statuses[event.event_id] = GroundTruthValidationStatus.VALIDATION_FAILED.value
                elif event.event_id in outcome.confirmed_event_ids:
                    event_statuses[event.event_id] = GroundTruthValidationStatus.VALIDATED_POSITIVE.value
                else:
                    event_statuses[event.event_id] = GroundTruthValidationStatus.VALIDATED_NORMAL.value

        provenance_failures = (
            list(schema_record.observed_evidence.get("violations", ()))
            if schema_record.result in {ValidationResult.FAIL, ValidationResult.ERROR}
            else []
        )
        deterministic_failures = sorted(
            trace_id for trace_id, outcome in outcomes.items()
            if outcome.deterministic_failed
        )
        mandatory_reasons: list[str] = []
        if deterministic_failures:
            mandatory_reasons.append(
                "deterministic invariant failures: " + ", ".join(deterministic_failures)
            )
        if not_confirmed:
            mandatory_reasons.append("supported intended anomaly candidate not confirmed")
        if gt_failures:
            mandatory_reasons.append("ground-truth/injection consistency failure")
        if provenance_failures:
            mandatory_reasons.append("required schema/provenance incomplete")
        if persistence_record.result in {ValidationResult.FAIL, ValidationResult.ERROR}:
            mandatory_reasons.append("persistent enrollment continuity failure")
        if any(record.result in {ValidationResult.FAIL, ValidationResult.ERROR} for record in hard_negative_records):
            mandatory_reasons.append("declared hard-negative candidate violates supported checks")
        if internal_error_traces:
            mandatory_reasons.append("mandatory validator internal error")

        if provenance_failures or persistence_record.result in {
            ValidationResult.FAIL,
            ValidationResult.ERROR,
        }:
            for events, context in sequences:
                trace_statuses[context.trace_id] = GroundTruthValidationStatus.VALIDATION_FAILED.value
                for event in events:
                    event_statuses[event.event_id] = GroundTruthValidationStatus.VALIDATION_FAILED.value

        return ValidationReport(
            records=records,
            behavior_model_version=provenance.behavior_model_version,
            generator_version=provenance.generator_software_version,
            generator_git_commit=provenance.generator_git_commit,
            event_schema_version=provenance.event_schema_version,
            feature_schema_version=provenance.feature_schema_version,
            traces_checked=len(sequences),
            events_checked=sum(len(events) for events, _ in sequences),
            trace_ground_truth_statuses=trace_statuses,
            event_ground_truth_statuses=event_statuses,
            validated_positive_event_ids=positive_event_ids,
            unexpected_normal_trace_failures=unexpected_normal,
            intended_candidates_confirmed=confirmed,
            intended_candidates_not_confirmed=not_confirmed,
            gt_consistency_failures=gt_failures,
            provenance_schema_failures=provenance_failures,
            build_gate_passed=not mandatory_reasons,
            mandatory_failure_reasons=mandatory_reasons,
        )

    def _validate_trace(self, events: list[AuthEvent], context: Any) -> _TraceOutcome:
        records = [
            self._check_state_result(events, context),
            self._check_lifecycle(events, context),
            self._check_temporal(events, context),
            self._check_identity(events, context),
            self._check_token_binding(events, context),
            self._check_session_continuity(events, context),
            self._check_authorization(events, context),
        ]
        intended = {
            record.get("anomaly_variant_name")
            for record in context.injection_records
            if record.get("anomaly_variant_name") in supported_synchronized_variants()
        }
        intended.discard(None)
        confirmed_events: set[str] = set()
        confirmed_variants: set[str] = set()

        for variant in sorted(intended):
            record = (
                self._check_nonce_reuse(events, context)
                if variant == "nonce_reuse"
                else self._check_timestamp_inconsistency(events, context)
            )
            records.append(record)
            if record.result is ValidationResult.PASS:
                confirmed_variants.add(variant)
                confirmed_events.update(record.event_references[-1:])

        if not intended:
            records.append(self._record(
                "c1.7.supported_candidate.not_applicable",
                ValidationCategory.REPLAY_SINGLE_USE,
                context,
                "supported anomaly evidence is checked when declared",
                {"declared_supported_variants": []},
                ValidationResult.NOT_APPLICABLE,
                "trace declares no supported injected candidate",
            ))

        gt_record = self._check_ground_truth(
            events, context, confirmed_events, confirmed_variants, intended
        )
        records.append(gt_record)
        deterministic_failed = any(
            record.validation_category in self._DETERMINISTIC_CATEGORIES
            and record.result in {ValidationResult.FAIL, ValidationResult.ERROR}
            for record in records
        )
        return _TraceOutcome(
            records,
            confirmed_events,
            confirmed_variants,
            set(intended),
            deterministic_failed,
            gt_record.result is ValidationResult.FAIL,
        )

    def _check_state_result(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        successful_auth_seen = False
        validated_token_ids: set[str] = set()
        session_open_ids: set[str] = set()
        for event in events:
            if (
                event.event_type == EventType.AUTHENTICATION_SUCCESS
                and event.result is EventResult.SUCCESS
            ):
                if not event.authenticated_context_active:
                    violations.append({"event_id": event.event_id, "issue": "authentication_success_without_active_context"})
                else:
                    successful_auth_seen = True
            if event.event_type == EventType.AUTHENTICATION_FAILURE:
                if event.result is not EventResult.FAILURE or event.new_state != AuthState.AUTH_FAILED:
                    violations.append({"event_id": event.event_id, "issue": "authentication_failure_result_state_mismatch"})
                if event.authenticated_context_active and not successful_auth_seen:
                    violations.append({"event_id": event.event_id, "issue": "failure_established_authenticated_context"})
            if event.authenticated_context_active and not successful_auth_seen:
                violations.append({"event_id": event.event_id, "issue": "active_auth_context_without_success_evidence"})
            if event.event_type == EventType.TOKEN_VALIDATED and event.result is EventResult.SUCCESS:
                if event.token_id:
                    validated_token_ids.add(event.token_id)
            if event.token_context_active and not validated_token_ids:
                violations.append({"event_id": event.event_id, "issue": "active_token_context_without_validation_success"})
            if event.event_type == EventType.TOKEN_REJECTED and (
                event.token_validation_result != "rejected" or event.token_context_active
            ):
                violations.append({"event_id": event.event_id, "issue": "token_rejection_established_valid_context"})
            if event.event_type == EventType.SESSION_OPENED and event.result is EventResult.SUCCESS:
                if event.protected_session_id:
                    session_open_ids.add(event.protected_session_id)
            if event.protected_session_active and event.protected_session_id not in session_open_ids:
                violations.append({"event_id": event.event_id, "issue": "active_session_without_open_success"})
            if (
                event.event_type in {EventType.SESSION_CLOSED, EventType.DISCONNECT, EventType.TIMEOUT}
                and event.result is EventResult.SUCCESS
                and (
                event.authenticated_context_active or event.token_context_active or event.protected_session_active
                )
            ):
                violations.append({"event_id": event.event_id, "issue": "termination_left_session_local_context_active"})
        if any(
            event.event_type in {EventType.SESSION_CLOSED, EventType.DISCONNECT, EventType.TIMEOUT}
            and event.result is EventResult.SUCCESS
            for event in events
        ) and not context.persistent_enrolled:
            violations.append({"issue": "ordinary_termination_erased_or_lacks_persistent_enrollment"})
        return self._violations_record(
            "c1.7.state_result.supported_subset",
            ValidationCategory.STATE_RESULT,
            "state/transition validity",
            context,
            "failures cannot establish success context; dependent context needs success evidence; termination clears only session-local context",
            violations,
        )

    def _check_lifecycle(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        auth_success_attempts: set[str] = set()
        issued: set[str] = set()
        presented: set[str] = set()
        validated: set[str] = set()
        opened: set[str] = set()
        access_requests: set[str] = set()
        for event in events:
            succeeded = event.result is EventResult.SUCCESS
            if event.event_type == EventType.AUTHENTICATION_SUCCESS and succeeded and event.auth_attempt_id:
                auth_success_attempts.add(event.auth_attempt_id)
            elif event.event_type == EventType.TOKEN_ISSUED and succeeded:
                if event.auth_attempt_id not in auth_success_attempts:
                    violations.append({"event_id": event.event_id, "issue": "token_before_authentication_success"})
                if event.token_id:
                    issued.add(event.token_id)
            elif event.event_type == EventType.TOKEN_PRESENTED and succeeded:
                if event.token_id not in issued:
                    violations.append({"event_id": event.event_id, "issue": "presentation_without_matching_issuance"})
                if event.token_id:
                    presented.add(event.token_id)
            elif event.event_type == EventType.TOKEN_VALIDATED and succeeded:
                if event.token_id not in presented:
                    violations.append({"event_id": event.event_id, "issue": "validation_without_matching_presentation"})
                if event.token_id:
                    validated.add(event.token_id)
            elif event.event_type == EventType.SESSION_OPENED and succeeded:
                if event.token_id not in validated:
                    violations.append({"event_id": event.event_id, "issue": "session_open_without_validated_token"})
                if event.protected_session_id:
                    opened.add(event.protected_session_id)
            elif event.event_type == EventType.ACCESS_REQUEST:
                if succeeded and event.protected_session_id not in opened:
                    violations.append({"event_id": event.event_id, "issue": "access_request_before_session_open"})
                if event.access_request_id:
                    access_requests.add(event.access_request_id)
            elif (
                event.event_type == EventType.RETRY
                and event.previous_state == AuthState.ACCESS_DENIED
                and event.access_request_id
            ):
                # C1.3 represents the new access-decision/request context on
                # the retry event rather than emitting a second ACCESS_REQUEST.
                access_requests.add(event.access_request_id)
            elif (
                event.event_type == EventType.ACCESS_GRANTED
                and event.result is EventResult.SUCCESS
            ) or (
                event.event_type == EventType.ACCESS_DENIED
                and event.authorization_decision == "denied"
            ):
                if event.access_request_id not in access_requests:
                    violations.append({"event_id": event.event_id, "issue": "access_outcome_without_request"})
        return self._violations_record(
            "c1.7.lifecycle_causal.supported_subset",
            ValidationCategory.LIFECYCLE_CAUSAL,
            "lifecycle/causal ordering",
            context,
            "successful security operations have their required causal predecessors",
            violations,
        )

    def _check_temporal(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        for previous, current in zip(events, events[1:]):
            if current.timestamp <= previous.timestamp:
                violations.append({"event_id": current.event_id, "issue": "semantic_time_not_strictly_monotonic", "previous": previous.timestamp, "current": current.timestamp})
        unresolved_failures: list[AuthEvent] = []
        token_issued: dict[str, AuthEvent] = {}
        token_presented: dict[str, AuthEvent] = {}
        sessions_opened: dict[str, AuthEvent] = {}
        renewals: list[AuthEvent] = []
        for event in events:
            if event.result is EventResult.FAILURE:
                unresolved_failures.append(event)
            elif event.event_type == EventType.RETRY:
                if not unresolved_failures or event.timestamp <= unresolved_failures[-1].timestamp:
                    violations.append({"event_id": event.event_id, "issue": "retry_without_earlier_failure"})
                elif event.previous_state == AuthState.AUTH_FAILED:
                    failure = unresolved_failures[-1]
                    if (
                        failure.event_type != EventType.AUTHENTICATION_FAILURE
                        or not failure.auth_attempt_id
                        or not event.auth_attempt_id
                        or failure.auth_attempt_id == event.auth_attempt_id
                    ):
                        violations.append({"event_id": event.event_id, "issue": "authentication_retry_attempt_context_incoherent"})
                unresolved_failures.clear()
            if event.event_type == EventType.TOKEN_ISSUED and event.result is EventResult.SUCCESS and event.token_id:
                token_issued[event.token_id] = event
            elif event.event_type == EventType.TOKEN_PRESENTED and event.result is EventResult.SUCCESS and event.token_id:
                issued = token_issued.get(event.token_id)
                if not issued or event.timestamp <= issued.timestamp:
                    violations.append({"event_id": event.event_id, "issue": "token_presentation_time_precedes_issuance"})
                token_presented[event.token_id] = event
            elif event.event_type == EventType.TOKEN_VALIDATED and event.result is EventResult.SUCCESS and event.token_id:
                presented = token_presented.get(event.token_id)
                if not presented or event.timestamp <= presented.timestamp:
                    violations.append({"event_id": event.event_id, "issue": "token_validation_time_precedes_presentation"})
                if event.token_expiry is None or event.timestamp > event.token_expiry:
                    violations.append({"event_id": event.event_id, "issue": "token_validated_after_or_without_expiry_evidence"})
            elif event.event_type == EventType.SESSION_OPENED and event.result is EventResult.SUCCESS and event.protected_session_id:
                sessions_opened[event.protected_session_id] = event
            elif event.event_type in {EventType.SESSION_CLOSED, EventType.DISCONNECT, EventType.TIMEOUT} and event.protected_session_id:
                opened = sessions_opened.get(event.protected_session_id)
                if not opened or event.timestamp <= opened.timestamp:
                    violations.append({"event_id": event.event_id, "issue": "session_termination_not_after_open"})
            elif event.event_type == EventType.RENEWAL_REQUEST and event.result is EventResult.SUCCESS:
                renewals.append(event)
        if context.renewed_token_issued_at is not None:
            if not renewals or context.renewal_requested_at is None or context.renewed_token_issued_at <= context.renewal_requested_at:
                violations.append({"issue": "renewed_token_not_after_renewal_request"})
        return self._violations_record(
            "c1.7.temporal.supported_subset",
            ValidationCategory.TEMPORAL,
            "temporal/freshness consistency",
            context,
            "authoritative semantic chronology and enforced validity relationships are coherent",
            violations,
        )

    def _check_identity(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        for event in events:
            if event.device_id != context.device_id or event.trace_id != context.trace_id or event.scenario_id != context.scenario_id or event.session_id != context.legacy_session_id:
                violations.append({"event_id": event.event_id, "issue": "trace_or_device_identity_context_mismatch"})
            if event.authenticated_identity is not None and event.authenticated_identity != context.device_id:
                violations.append({"event_id": event.event_id, "issue": "authenticated_identity_mismatch"})
        return self._violations_record(
            "c1.7.identity.supported_subset",
            ValidationCategory.IDENTITY,
            "identity consistency",
            context,
            "represented device, trace, session, and authenticated identity references remain coherent",
            violations,
        )

    def _check_token_binding(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        issued: set[str] = set()
        presented: set[str] = set()
        for event in events:
            if event.event_type == EventType.TOKEN_ISSUED and event.result is EventResult.SUCCESS:
                if not event.authenticated_context_active or not event.token_id:
                    violations.append({"event_id": event.event_id, "issue": "token_issued_without_authenticated_context_or_id"})
                elif event.token_id:
                    issued.add(event.token_id)
            elif event.event_type == EventType.TOKEN_PRESENTED and event.result is EventResult.SUCCESS:
                if event.token_id not in issued:
                    violations.append({"event_id": event.event_id, "issue": "presented_token_not_issued_in_trace"})
                if event.token_id:
                    presented.add(event.token_id)
            elif event.event_type == EventType.TOKEN_VALIDATED and event.result is EventResult.SUCCESS:
                if event.token_id not in presented or event.token_validation_result != "validated":
                    violations.append({"event_id": event.event_id, "issue": "validated_token_not_presented_or_not_marked_validated"})
            if event.event_type == EventType.ACCESS_GRANTED and event.result is EventResult.SUCCESS:
                if not event.token_scope or not event.resource_id or not event.requested_action:
                    violations.append({"event_id": event.event_id, "issue": "grant_lacks_scope_resource_action_evidence"})
                else:
                    try:
                        scope_resource, permission = event.token_scope.split(":", 1)
                        requested_resource = event.resource_id.split("/", 3)[-1].split("/", 1)[0]
                    except (ValueError, AttributeError):
                        violations.append({"event_id": event.event_id, "issue": "malformed_scope_or_resource"})
                    else:
                        if requested_resource != scope_resource or (
                            permission != "readwrite" and permission != event.requested_action
                        ):
                            violations.append({"event_id": event.event_id, "issue": "grant_outside_reference_scope"})
        return self._violations_record(
            "c1.7.credential_token.supported_subset",
            ValidationCategory.CREDENTIAL_TOKEN,
            "credential/token binding",
            context,
            "issued, presented, validated, and used token evidence retains implemented identity/context/scope relationships",
            violations,
        )

    def _check_session_continuity(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        declared_attempts = set(context.auth_attempt_ids)
        event_attempts = {event.auth_attempt_id for event in events if event.auth_attempt_id}
        if not event_attempts.issubset(declared_attempts):
            violations.append({"issue": "event_auth_attempt_not_declared_by_trace", "unexpected": sorted(event_attempts - declared_attempts)})
        session_ids = {event.protected_session_id for event in events if event.protected_session_id}
        if session_ids and session_ids != {context.protected_session_id}:
            violations.append({"issue": "mixed_protected_session_context", "observed": sorted(session_ids)})
        renewal_events = [event for event in events if event.event_type == EventType.RENEWAL_REQUEST and event.result is EventResult.SUCCESS]
        for event in renewal_events:
            if event.auth_attempt_id not in set(context.renewal_auth_attempt_ids):
                violations.append({"event_id": event.event_id, "issue": "renewal_attempt_not_declared"})
            if event.protected_session_id != context.refreshes_protected_session_id:
                violations.append({"event_id": event.event_id, "issue": "renewal_not_linked_to_refreshed_session"})
        return self._violations_record(
            "c1.7.session_continuity.supported_subset",
            ValidationCategory.SESSION_CONTINUITY,
            "session continuity/context",
            context,
            "attempt and protected-session references remain within the intended trace/device context",
            violations,
        )

    def _check_authorization(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        for event in events:
            if event.event_type == EventType.ACCESS_GRANTED and event.result is EventResult.SUCCESS:
                required = (
                    event.authenticated_context_active
                    and event.authenticated_identity == event.device_id
                    and event.token_context_active
                    and event.token_validation_result == "validated"
                    and event.protected_session_active
                    and event.authorization_decision == "granted"
                    and event.resource_operation_outcome == "success"
                )
                if not required:
                    violations.append({"event_id": event.event_id, "issue": "grant_missing_security_precondition_or_outcome"})
            elif event.event_type == EventType.ACCESS_DENIED:
                if event.authorization_decision != "denied" or event.resource_operation_outcome not in {"denied", "not_executed"}:
                    violations.append({"event_id": event.event_id, "issue": "denial_decision_outcome_mismatch"})
        return self._violations_record(
            "c1.7.authorization_access.supported_subset",
            ValidationCategory.AUTHORIZATION_ACCESS,
            "authorization/access preconditions",
            context,
            "grants have explicit authentication/token/session/authorization evidence and denials do not execute successfully",
            violations,
        )

    def _check_nonce_reuse(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        groups: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in events:
            if event.nonce and event.auth_attempt_id:
                groups[event.nonce].append(event)
        candidates: list[tuple[AuthEvent, AuthEvent]] = []
        for occurrences in groups.values():
            for index, first in enumerate(occurrences):
                for second in occurrences[index + 1:]:
                    if first.auth_attempt_id != second.auth_attempt_id:
                        candidates.append((first, second))
        record = next(
            item for item in context.injection_records
            if item.get("anomaly_variant_name") == "nonce_reuse"
        )
        linked_pair = next((pair for pair in candidates if pair[0].event_id in set(record.get("source_evidence_event_ids", ())) and pair[1].event_id == next((event.event_id for event in events if event.injection_id == record.get("injection_id")), None)), None)
        valid_scope = record.get("declared_history_scope") == "within_trace_across_authentication_attempts"
        passed = linked_pair is not None and valid_scope
        references = tuple(event.event_id for event in linked_pair) if linked_pair else ()
        return self._record(
            "c1.7.nonce_reuse.within_trace_attempts",
            ValidationCategory.REPLAY_SINGLE_USE,
            context,
            "same nonce is evidenced in distinct authentication attempts and source/reuse linkage is reconstructable in the declared supported scope",
            {
                "repeated_nonce_pairs_across_attempts": [
                    {"source_event_id": first.event_id, "reuse_event_id": second.event_id,
                     "source_auth_attempt_id": first.auth_attempt_id, "reuse_auth_attempt_id": second.auth_attempt_id,
                     "same_material": first.nonce == second.nonce}
                    for first, second in candidates
                ],
                "declared_scope": record.get("declared_history_scope"),
                "linked_pair_found": linked_pair is not None,
            },
            ValidationResult.PASS if passed else ValidationResult.FAIL,
            "observable nonce-reuse evidence confirmed" if passed else "declared nonce reuse is not supported by emitted linked evidence",
            invariant_family="replay/single-use and temporal/freshness consistency",
            event_references=references,
        )

    def _check_timestamp_inconsistency(self, events: list[AuthEvent], context: Any) -> ValidationRecord:
        record = next(
            item for item in context.injection_records
            if item.get("anomaly_variant_name") == "timestamp_inconsistency"
        )
        source_ids = set(record.get("source_evidence_event_ids", ()))
        source = next((event for event in events if event.event_id in source_ids), None)
        target = next((event for event in events if event.injection_id == record.get("injection_id")), None)
        source_observed = (
            source.observed_timestamp if source and source.observed_timestamp is not None
            else source.timestamp if source else None
        )
        target_observed = (
            target.observed_timestamp if target and target.observed_timestamp is not None
            else target.timestamp if target else None
        )
        semantic_coherent = bool(source and target and source.timestamp < target.timestamp)
        observed_violation = bool(
            source_observed is not None and target_observed is not None
            and target_observed < source_observed
        )
        targeted_relation = bool(
            target and target.targeted_temporal_relationship
            == "declared_event_time_after_predecessor"
        )
        passed = semantic_coherent and observed_violation and targeted_relation
        references = tuple(
            event.event_id for event in (source, target) if event is not None
        )
        return self._record(
            "c1.7.timestamp_inconsistency.causal_predecessor",
            ValidationCategory.TIMESTAMP_EVIDENCE,
            context,
            "semantic predecessor order remains coherent while observed target time violates the declared after-predecessor relation",
            {
                "source_semantic_timestamp": source.timestamp if source else None,
                "target_semantic_timestamp": target.timestamp if target else None,
                "source_observed_timestamp": source_observed,
                "target_observed_timestamp": target_observed,
                "semantic_order_coherent": semantic_coherent,
                "observed_order_violated": observed_violation,
                "targeted_relation_present": targeted_relation,
            },
            ValidationResult.PASS if passed else ValidationResult.FAIL,
            "observable timestamp violation confirmed" if passed else "declared timestamp candidate is not supported by emitted temporal evidence",
            invariant_family="temporal/freshness consistency",
            event_references=references,
        )

    def _check_ground_truth(
        self,
        events: list[AuthEvent],
        context: Any,
        confirmed_event_ids: set[str],
        confirmed_variants: set[str],
        intended_variants: set[str],
    ) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        positive_events = {event.event_id for event in events if event.anomaly_label}
        if positive_events != confirmed_event_ids:
            violations.append({"issue": "event_gt_does_not_equal_validated_deviation_evidence", "positive_event_ids": sorted(positive_events), "validated_event_ids": sorted(confirmed_event_ids)})
        expected_trace_positive = bool(confirmed_variants)
        if bool(context.observable_anomaly) != expected_trace_positive:
            violations.append({"issue": "trace_gt_not_supported_by_validated_evidence", "trace_gt": bool(context.observable_anomaly), "validated_positive": expected_trace_positive})
        if bool(context.observable_violation_candidate) != expected_trace_positive:
            violations.append({"issue": "candidate_status_not_supported_by_validated_evidence"})
        if context.attack_scenario_intent and not confirmed_variants and context.observable_anomaly:
            violations.append({"issue": "scenario_intent_only_trace_labeled_anomalous"})
        if intended_variants != confirmed_variants:
            violations.append({"issue": "supported_intended_candidate_not_confirmed", "intended": sorted(intended_variants), "confirmed": sorted(confirmed_variants)})
        return self._violations_record(
            "c1.7.ground_truth.consistency",
            ValidationCategory.GROUND_TRUTH,
            "ground-truth consistency",
            context,
            "event/trace GT follows independently validated observable evidence, never intent or injection status alone",
            violations,
        )

    def _validate_cross_trace_persistence(self, sequences: list[tuple[list[AuthEvent], Any]]) -> ValidationRecord:
        violations: list[dict[str, Any]] = []
        enrolled_by_device: dict[str, bool] = defaultdict(bool)
        for _events, context in sequences:
            if enrolled_by_device[context.device_id] and not context.persistent_enrolled:
                violations.append({"trace_id": context.trace_id, "device_id": context.device_id, "issue": "persistent_enrollment_regressed_across_traces"})
            enrolled_by_device[context.device_id] = enrolled_by_device[context.device_id] or context.persistent_enrolled
        return ValidationRecord(
            validation_id="c1.7.persistence.cross_trace_enrollment",
            validation_category=ValidationCategory.SESSION_CONTINUITY,
            invariant_family="session continuity/context",
            invariant_identifier=None,
            trace_id=None,
            device_id=None,
            protected_session_id=None,
            event_references=(),
            expected_condition="once observed enrolled, ordinary later traces for that device retain enrollment",
            observed_evidence={"violations": violations},
            result=ValidationResult.FAIL if violations else ValidationResult.PASS,
            reason="persistent enrollment regression found" if violations else "cross-trace enrollment persistence confirmed",
        )

    def _validate_schema_provenance(
        self,
        sequences: list[tuple[list[AuthEvent], Any]],
        provenance: GenerationProvenance,
        field_manifest: Optional[dict[str, Any]],
        dataset_manifest: Optional[dict[str, Any]],
    ) -> ValidationRecord:
        violations: list[str] = []
        required_generation = {
            "behavior_model_version": provenance.behavior_model_version,
            "generator_version": provenance.generator_software_version,
            "generator_git_commit": provenance.generator_git_commit,
            "event_schema_version": provenance.event_schema_version,
            "feature_schema_version": provenance.feature_schema_version,
            "run_id": provenance.run_id,
            "configuration_version": provenance.configuration_version,
            "configuration_snapshot_reference": provenance.configuration_snapshot_reference,
            "configuration_snapshot": provenance.configuration_snapshot,
        }
        for name, value in required_generation.items():
            if value is None or value == "" or value == {}:
                violations.append(f"missing generation provenance: {name}")
        if provenance.behavior_model_version != BEHAVIOR_MODEL_VERSION:
            violations.append("behavior-model version does not match validator contract")
        if not provenance.configuration_snapshot_reference.startswith("sha256:"):
            violations.append("configuration snapshot reference is not content-addressed")
        seed = provenance.configuration_snapshot.get("simulation", {}).get("random_seed")
        if seed is None:
            violations.append("missing randomness master seed")
        if not field_manifest or not field_manifest.get("fields"):
            violations.append("missing field manifest")
        elif any(
            not item.get("field_name")
            or not item.get("export_view")
            or not item.get("role")
            or not item.get("availability")
            for item in field_manifest["fields"]
        ):
            violations.append("field manifest contains incomplete field definitions")
        if not dataset_manifest:
            violations.append("missing dataset manifest")
        else:
            for name in (
                "dataset_interface_version", "behavior_model_version",
                "event_schema_version", "feature_schema_version", "run_id",
            ):
                if not dataset_manifest.get(name):
                    violations.append(f"missing dataset manifest field: {name}")
            for name, expected in (
                ("behavior_model_version", provenance.behavior_model_version),
                ("event_schema_version", provenance.event_schema_version),
                ("feature_schema_version", provenance.feature_schema_version),
                ("run_id", provenance.run_id),
            ):
                if dataset_manifest.get(name) != expected:
                    violations.append(f"dataset manifest mismatch: {name}")
        trace_ids = [context.trace_id for _, context in sequences]
        if len(trace_ids) != len(set(trace_ids)):
            violations.append("trace identifiers are not unique")
        event_ids = [event.event_id for events, _ in sequences for event in events]
        if len(event_ids) != len(set(event_ids)):
            violations.append("event identifiers are not unique")
        for events, context in sequences:
            if context.generation_profile != SYNCHRONIZED_GENERATION_PROFILE:
                violations.append(f"trace {context.trace_id}: non-synchronized generation profile")
            for name in ("trace_id", "scenario_id", "device_id", "legacy_session_id"):
                if not getattr(context, name, None):
                    violations.append(f"trace context missing {name}")
            for event in events:
                for name in ("event_id", "trace_id", "scenario_id", "device_id", "session_id"):
                    if not getattr(event, name, None):
                        violations.append(f"event {event.event_id}: missing {name}")
                if event.auth_attempt_id and event.auth_attempt_id not in set(context.auth_attempt_ids):
                    violations.append(f"event {event.event_id}: auth attempt absent from trace provenance")
                if event.event_type in {
                    EventType.AUTHENTICATION_REQUEST,
                    EventType.CHALLENGE_SENT,
                    EventType.NONCE_RECEIVED,
                    EventType.RESPONSE_SENT,
                    EventType.AUTHENTICATION_SUCCESS,
                    EventType.AUTHENTICATION_FAILURE,
                    EventType.TOKEN_ISSUED,
                    EventType.TOKEN_PRESENTED,
                    EventType.TOKEN_VALIDATED,
                    EventType.TOKEN_REJECTED,
                    EventType.RENEWAL_REQUEST,
                } and not event.auth_attempt_id:
                    violations.append(f"event {event.event_id}: missing applicable auth attempt id")
                if (
                    event.result is EventResult.SUCCESS
                    and event.event_type in {
                        EventType.SESSION_OPENED,
                        EventType.SESSION_CLOSED,
                        EventType.ACCESS_REQUEST,
                        EventType.ACCESS_GRANTED,
                    }
                    and not event.protected_session_id
                ):
                    violations.append(f"event {event.event_id}: missing applicable protected session id")
            injection_ids = {
                record.get("injection_id") for record in context.injection_records
                if record.get("injection_id")
            }
            for record in context.injection_records:
                for name in (
                    "injection_id", "anomaly_variant_name", "trace_id", "device_id",
                    "session_id", "declared_history_scope", "validation_status",
                ):
                    if not record.get(name):
                        violations.append(f"trace {context.trace_id}: injection record missing {name}")
            for event in events:
                if event.injection_id and event.injection_id not in injection_ids:
                    violations.append(f"event {event.event_id}: injection id lacks trace provenance")
            if context.observable_violation_candidate and not context.injection_records:
                violations.append(f"trace {context.trace_id}: candidate lacks injection provenance")
        return ValidationRecord(
            validation_id="c1.7.schema_provenance.mandatory",
            validation_category=ValidationCategory.SCHEMA_PROVENANCE,
            invariant_family=None,
            invariant_identifier=None,
            trace_id=None,
            device_id=None,
            protected_session_id=None,
            event_references=(),
            expected_condition="mandatory synchronized schema, run, configuration, randomness, identifier, and injection provenance is complete",
            observed_evidence={"violations": violations},
            result=ValidationResult.FAIL if violations else ValidationResult.PASS,
            reason="mandatory metadata incomplete" if violations else "mandatory metadata complete",
        )

    def _validate_hard_negative_candidates(
        self,
        sequences: list[tuple[list[AuthEvent], Any]],
        outcomes: dict[str, _TraceOutcome],
        hard_negative_trace_ids: Optional[Iterable[str]],
    ) -> list[ValidationRecord]:
        requested = set(hard_negative_trace_ids or ())
        if not requested:
            return [ValidationRecord(
                validation_id="c1.7.hard_negative.not_applicable",
                validation_category=ValidationCategory.HARD_NEGATIVE,
                invariant_family=None,
                invariant_identifier=None,
                trace_id=None,
                device_id=None,
                protected_session_id=None,
                event_references=(),
                expected_condition="declared hard-negative candidate has no supported deterministic violation",
                observed_evidence={"candidate_count": 0},
                result=ValidationResult.NOT_APPLICABLE,
                reason="no hard-negative candidates declared",
            )]
        contexts = {context.trace_id: context for _, context in sequences}
        result: list[ValidationRecord] = []
        for trace_id in sorted(requested):
            context = contexts.get(trace_id)
            outcome = outcomes.get(trace_id)
            valid = bool(outcome and not outcome.deterministic_failed and not outcome.confirmed_variants and not outcome.gt_failed)
            result.append(self._record(
                "c1.7.hard_negative.candidate_validity",
                ValidationCategory.HARD_NEGATIVE,
                context,
                "candidate has no supported deterministic or observable invariant violation",
                {"trace_found": context is not None, "validated_variants": sorted(outcome.confirmed_variants) if outcome else [], "deterministic_failed": outcome.deterministic_failed if outcome else None},
                ValidationResult.PASS if valid else ValidationResult.FAIL,
                "hard-negative candidate remains semantically valid" if valid else "hard-negative candidate is missing or violates a supported check",
            ))
        return result

    def _unsupported_records(self) -> list[ValidationRecord]:
        unsupported = {
            "replay_token": "approved reuse-forbidden domain not implemented",
            "duplicate_sequence": "semantic subsequence duplication not implemented",
            "abnormal_failure_rate": "history window and threshold/baseline unresolved",
            "abnormal_renewal": "behavioral history and baseline unresolved",
            "impersonation": "composite scenario lacks decomposed semantic variants",
            "identity_token_mismatch": "composite scenario lacks decomposed semantic variants",
            "access_without_auth": "composite scenario lacks explicit violated prerequisite variant",
            "cross_session_replay_or_nonce": "cross-session material history not implemented",
            "statistical_behavioral_baselines": "statistical semantics not established",
            "global_concurrency_invariants": "global concurrency not implemented",
            "operational_trace_validation": "operational trace support not implemented",
        }
        return [ValidationRecord(
            validation_id=f"c1.7.unsupported.{name}",
            validation_category=ValidationCategory.UNSUPPORTED_CAPABILITY,
            invariant_family=None,
            invariant_identifier=None,
            trace_id=None,
            device_id=None,
            protected_session_id=None,
            event_references=(),
            expected_condition="validator must not claim support outside the synchronized subset",
            observed_evidence={"capability": name},
            result=ValidationResult.UNSUPPORTED,
            reason=reason,
        ) for name, reason in unsupported.items()]

    def _violations_record(
        self,
        validation_id: str,
        category: ValidationCategory,
        invariant_family: Optional[str],
        context: Any,
        expected: str,
        violations: list[dict[str, Any]],
    ) -> ValidationRecord:
        return self._record(
            validation_id,
            category,
            context,
            expected,
            {"violations": violations},
            ValidationResult.FAIL if violations else ValidationResult.PASS,
            "evidence violates expected condition" if violations else "applicable evidence satisfies expected condition",
            invariant_family=invariant_family,
            event_references=tuple(
                item["event_id"] for item in violations if item.get("event_id")
            ),
        )

    @staticmethod
    def _record(
        validation_id: str,
        category: ValidationCategory,
        context: Any,
        expected: str,
        observed: dict[str, Any],
        result: ValidationResult,
        reason: str,
        *,
        invariant_family: Optional[str] = None,
        event_references: tuple[str, ...] = (),
    ) -> ValidationRecord:
        return ValidationRecord(
            validation_id=validation_id,
            validation_category=category,
            invariant_family=invariant_family,
            invariant_identifier=None,
            trace_id=getattr(context, "trace_id", None),
            device_id=getattr(context, "device_id", None),
            protected_session_id=getattr(context, "protected_session_id", None),
            event_references=event_references,
            expected_condition=expected,
            observed_evidence=observed,
            result=result,
            reason=reason,
        )


def validate_synchronized_dataset(
    sequences: list[tuple[list[AuthEvent], Any]],
    *,
    provenance: GenerationProvenance,
    field_manifest: Optional[dict[str, Any]],
    dataset_manifest: Optional[dict[str, Any]],
    hard_negative_trace_ids: Optional[Iterable[str]] = None,
) -> ValidationReport:
    return DatasetValidator().validate(
        sequences,
        provenance=provenance,
        field_manifest=field_manifest,
        dataset_manifest=dataset_manifest,
        hard_negative_trace_ids=hard_negative_trace_ids,
    )
