"""C1.7 independent semantic dataset-validator tests."""

import copy
import json
import random
import unittest
from unittest.mock import patch

from simulator.anomaly_contract import SYNCHRONIZED_GENERATION_PROFILE
from simulator.config.settings import cfg
from simulator.data.dataset_contract import dataset_capability_manifest, field_manifest
from simulator.data.synchronized_views import build_synchronized_bundle
from simulator.engines.event_engine import EventEngine, STEALTH_FRACTION
from simulator.engines.scenario_engine import NORMAL_FLOW, ScenarioEngine, ScenarioSpec
from simulator.event_model import AuthState, EventType
from simulator.provenance import build_generation_provenance
from simulator.security_context import PersistentDeviceContext
from simulator.validation import (
    BuildGateError,
    VALIDATION_SCHEMA_VERSION,
    VALIDATOR_VERSION,
    ValidationCategory,
    ValidationResult,
    validate_synchronized_dataset,
)


def execute(spec, *, seed=701):
    random.seed(seed)
    spec.generation_profile = SYNCHRONIZED_GENERATION_PROFILE
    return EventEngine(
        device_id="device-validator",
        gateway_id="gateway-validator",
        auth_server_id="auth-validator",
        broker_id="broker-validator",
        start_time=20_000.0,
        persistent_context=PersistentDeviceContext(device_id="device-validator"),
    ).execute(spec)


def normal_pair(seed=701):
    return execute(ScenarioSpec(
        scenario_id=f"normal-{seed}",
        scenario_type="normal",
        is_anomaly=False,
        generation_profile=SYNCHRONIZED_GENERATION_PROFILE,
        normal_steps=list(NORMAL_FLOW),
    ), seed=seed)


def validate(sequences, *, field_data=None, dataset_data=None, hard_negative_ids=None):
    provenance = build_generation_provenance(
        cfg, run_id="validation-run", generator_git_commit="validation-commit"
    )
    fields = field_manifest() if field_data is None else field_data
    dataset = dataset_capability_manifest(
        provenance,
        generation_profiles=(context.generation_profile for _, context in sequences),
    ) if dataset_data is None else dataset_data
    return validate_synchronized_dataset(
        sequences,
        provenance=provenance,
        field_manifest=fields,
        dataset_manifest=dataset,
        hard_negative_trace_ids=hard_negative_ids,
    )


def category_record(report, category, trace_id=None):
    return next(
        record for record in report.records
        if record.validation_category is category
        and (trace_id is None or record.trace_id == trace_id)
    )


class ExecutableValidatorTests(unittest.TestCase):
    def test_coherent_normal_trace_passes_deterministic_categories_and_gate(self):
        events, context = normal_pair()
        report = validate([(events, context)])

        for category in (
            ValidationCategory.STATE_RESULT,
            ValidationCategory.LIFECYCLE_CAUSAL,
            ValidationCategory.TEMPORAL,
            ValidationCategory.IDENTITY,
            ValidationCategory.CREDENTIAL_TOKEN,
            ValidationCategory.SESSION_CONTINUITY,
            ValidationCategory.AUTHORIZATION_ACCESS,
            ValidationCategory.GROUND_TRUTH,
        ):
            self.assertEqual(
                ValidationResult.PASS,
                category_record(report, category, context.trace_id).result,
                category,
            )
        self.assertTrue(report.build_gate_passed)
        self.assertEqual("validated_normal", report.trace_ground_truth_statuses[context.trace_id])

    def test_result_state_failure_is_detected(self):
        events, context = execute(ScenarioEngine(71).normal_with_retry(), seed=711)
        failure = next(event for event in events if event.event_type == EventType.AUTHENTICATION_FAILURE)
        failure.new_state = AuthState.AUTHENTICATED

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.STATE_RESULT, context.trace_id).result,
        )
        self.assertIn(context.trace_id, report.unexpected_normal_trace_failures)
        self.assertFalse(report.build_gate_passed)

    def test_lifecycle_ordering_corruption_is_detected(self):
        events, context = normal_pair(721)
        events[:] = [event for event in events if event.event_type != EventType.TOKEN_ISSUED]

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.LIFECYCLE_CAUSAL, context.trace_id).result,
        )

    def test_temporal_ordering_and_token_validity_are_checked(self):
        events, context = normal_pair(731)
        issued = next(event for event in events if event.event_type == EventType.TOKEN_ISSUED)
        presented = next(event for event in events if event.event_type == EventType.TOKEN_PRESENTED)
        presented.timestamp = issued.timestamp

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.TEMPORAL, context.trace_id).result,
        )
        self.assertFalse(report.build_gate_passed)

    def test_expired_token_validation_is_detected(self):
        events, context = normal_pair(736)
        validated = next(
            event for event in events if event.event_type == EventType.TOKEN_VALIDATED
        )
        validated.token_expiry = validated.timestamp - 1.0

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.TEMPORAL, context.trace_id).result,
        )

    def test_token_binding_corruption_is_detected(self):
        events, context = normal_pair(741)
        presented = next(event for event in events if event.event_type == EventType.TOKEN_PRESENTED)
        presented.token_id = "not-the-issued-token"

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.CREDENTIAL_TOKEN, context.trace_id).result,
        )

    def test_session_context_mixing_is_detected(self):
        events, context = normal_pair(751)
        auth_event = next(event for event in events if event.auth_attempt_id)
        auth_event.auth_attempt_id = "foreign-attempt"

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.SESSION_CONTINUITY, context.trace_id).result,
        )

    def test_persistent_enrollment_regression_is_detected_across_traces(self):
        first_events, first_context = normal_pair(756)
        second_events, second_context = normal_pair(757)
        second_context.device_id = first_context.device_id
        for event in second_events:
            event.device_id = first_context.device_id
        second_context.persistent_enrolled = False

        report = validate([
            (first_events, first_context),
            (second_events, second_context),
        ])
        persistence = next(
            record for record in report.records
            if record.validation_id == "c1.7.persistence.cross_trace_enrollment"
        )
        self.assertEqual(ValidationResult.FAIL, persistence.result)
        self.assertFalse(report.build_gate_passed)

    def test_access_grant_without_security_evidence_fails_gate(self):
        events, context = normal_pair(761)
        grant = next(event for event in events if event.event_type == EventType.ACCESS_GRANTED)
        grant.authorization_decision = "denied"

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.AUTHORIZATION_ACCESS, context.trace_id).result,
        )
        self.assertFalse(report.build_gate_passed)

    def test_nonce_reuse_requires_repeated_linked_evidence_not_injection_flag(self):
        with patch.dict(STEALTH_FRACTION, {"nonce_reuse": 0.0}):
            events, context = execute(
                ScenarioEngine(77).synchronized_anomaly("nonce_reuse"), seed=771
            )
        initial = validate([(events, context)])
        self.assertIn(
            {"trace_id": context.trace_id, "variant": "nonce_reuse"},
            initial.intended_candidates_confirmed,
        )

        tampered_events = copy.deepcopy(events)
        tampered_context = copy.deepcopy(context)
        reused = next(event for event in tampered_events if event.injection_id)
        reused.nonce = "unique-replacement-nonce"
        # Metadata continues to claim the transformation and candidate.
        self.assertTrue(tampered_context.injection_records[0]["transformation_applied"])
        report = validate([(tampered_events, tampered_context)])

        self.assertTrue(report.intended_candidates_not_confirmed)
        self.assertFalse(report.build_gate_passed)
        self.assertEqual("validation_failed", report.trace_ground_truth_statuses[context.trace_id])

    def test_timestamp_candidate_requires_observed_order_violation(self):
        with patch.dict(STEALTH_FRACTION, {"timestamp_inconsistency": 0.0}):
            events, context = execute(
                ScenarioEngine(78).synchronized_anomaly("timestamp_inconsistency"),
                seed=781,
            )
        repaired_events = copy.deepcopy(events)
        repaired_context = copy.deepcopy(context)
        target = next(event for event in repaired_events if event.injection_id)
        target.observed_timestamp = target.timestamp

        report = validate([(repaired_events, repaired_context)])
        record = category_record(
            report, ValidationCategory.TIMESTAMP_EVIDENCE, context.trace_id
        )
        self.assertEqual(ValidationResult.FAIL, record.result)
        self.assertFalse(report.build_gate_passed)

    def test_injection_applied_flag_does_not_create_or_remove_evidence(self):
        with patch.dict(STEALTH_FRACTION, {"nonce_reuse": 0.0}):
            events, context = execute(
                ScenarioEngine(790).synchronized_anomaly("nonce_reuse"), seed=790
            )
        context.injection_records[0]["transformation_applied"] = False

        report = validate([(events, context)])
        record = category_record(report, ValidationCategory.REPLAY_SINGLE_USE, context.trace_id)
        self.assertEqual(ValidationResult.PASS, record.result)
        self.assertTrue(report.build_gate_passed)

    def test_stealth_intent_without_violation_validates_normal(self):
        with patch.dict(STEALTH_FRACTION, {"nonce_reuse": 1.0}):
            events, context = execute(
                ScenarioEngine(80).synchronized_anomaly("nonce_reuse"), seed=801
            )
        report = validate([(events, context)])

        self.assertTrue(context.attack_scenario_intent)
        self.assertFalse(context.observable_anomaly)
        self.assertEqual("validated_normal", report.trace_ground_truth_statuses[context.trace_id])
        self.assertTrue(report.build_gate_passed)

    def test_positive_gt_tampering_on_normal_trace_fails(self):
        events, context = normal_pair(811)
        events[0].anomaly_label = "nonce_reuse"
        context.observable_anomaly = True
        context.observable_violation_candidate = True

        report = validate([(events, context)])
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(report, ValidationCategory.GROUND_TRUTH, context.trace_id).result,
        )
        self.assertFalse(report.build_gate_passed)

    def test_schema_provenance_completeness_is_mandatory(self):
        events, context = normal_pair(821)
        report = validate([(events, context)], field_data={})
        record = category_record(report, ValidationCategory.SCHEMA_PROVENANCE)

        self.assertEqual(ValidationResult.FAIL, record.result)
        self.assertTrue(report.provenance_schema_failures)
        self.assertFalse(report.build_gate_passed)
        self.assertEqual("validation_failed", report.trace_ground_truth_statuses[context.trace_id])

    def test_unsupported_checks_are_never_reported_as_pass(self):
        events, context = normal_pair(831)
        report = validate([(events, context)])
        unsupported = [
            record for record in report.records
            if record.validation_category is ValidationCategory.UNSUPPORTED_CAPABILITY
        ]

        self.assertEqual(11, len(unsupported))
        self.assertTrue(all(record.result is ValidationResult.UNSUPPORTED for record in unsupported))

    def test_hard_negative_candidate_preparation(self):
        events, context = normal_pair(841)
        no_candidate = validate([(events, context)])
        self.assertEqual(
            ValidationResult.NOT_APPLICABLE,
            category_record(no_candidate, ValidationCategory.HARD_NEGATIVE).result,
        )

        candidate = validate(
            [(events, context)], hard_negative_ids={context.trace_id}
        )
        self.assertEqual(
            ValidationResult.PASS,
            category_record(candidate, ValidationCategory.HARD_NEGATIVE, context.trace_id).result,
        )

        invalid_events = copy.deepcopy(events)
        invalid_context = copy.deepcopy(context)
        grant = next(
            event for event in invalid_events if event.event_type == EventType.ACCESS_GRANTED
        )
        grant.authenticated_context_active = False
        invalid = validate(
            [(invalid_events, invalid_context)],
            hard_negative_ids={invalid_context.trace_id},
        )
        self.assertEqual(
            ValidationResult.FAIL,
            category_record(
                invalid, ValidationCategory.HARD_NEGATIVE, invalid_context.trace_id
            ).result,
        )
        self.assertFalse(invalid.build_gate_passed)

    def test_machine_report_contains_versions_counts_and_gate(self):
        events, context = normal_pair(851)
        payload = validate([(events, context)]).to_dict()

        self.assertEqual(VALIDATOR_VERSION, payload["validator_version"])
        self.assertEqual(VALIDATION_SCHEMA_VERSION, payload["validation_schema_version"])
        self.assertEqual(1, payload["traces_checked"])
        self.assertEqual(len(events), payload["events_checked"])
        self.assertIn("PASS", payload["result_counts"])
        self.assertIn("UNSUPPORTED", payload["result_counts"])
        self.assertTrue(payload["build_gate"]["passed"])
        self.assertIn("unsupported", payload["ground_truth_status_vocabulary"])
        json.loads(json.dumps(payload))

    def test_bundle_integrates_validation_into_gt_without_detector_leakage(self):
        events, context = normal_pair(856)
        provenance = build_generation_provenance(
            cfg, run_id="bundle-validation", generator_git_commit="validation-commit"
        )
        bundle = build_synchronized_bundle(
            [(events, context)], provenance=provenance
        )

        self.assertTrue(bundle["validation"]["build_gate"]["passed"])
        self.assertEqual(
            ["validated_normal"],
            bundle["ground_truth"]["traces"][0]["validation_statuses"],
        )
        self.assertNotIn("validation_status", bundle["detector_observations"][0])
        self.assertNotIn("validator_version", bundle["detector_observations"][0])

    def test_build_gate_can_be_enforced_by_callers(self):
        events, context = normal_pair(861)
        passing = validate([(events, context)])
        passing.require_build_gate()

        grant = next(event for event in events if event.event_type == EventType.ACCESS_GRANTED)
        grant.resource_operation_outcome = "denied"
        failing = validate([(events, context)])
        with self.assertRaises(BuildGateError):
            failing.require_build_gate()


if __name__ == "__main__":
    unittest.main()
