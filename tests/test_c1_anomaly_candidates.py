"""Focused C1.5 tests for synchronized anomaly evidence and quarantine."""

import random
import unittest
from unittest.mock import patch

from simulator.anomaly_contract import (
    SYNCHRONIZED_GENERATION_PROFILE,
    VARIANT_CAPABILITIES,
    VariantCapabilityStatus,
    supported_synchronized_variants,
    synchronized_capability_report,
)
from simulator.config.settings import cfg
from simulator.data.output_views import to_feature_df, to_json_log
from simulator.engines.event_engine import EventEngine, STEALTH_FRACTION
from simulator.engines.scenario_engine import (
    AUTH_PREFIX,
    NORMAL_FLOW_WITH_RENEWAL,
    NORMAL_FLOW_WITH_RETRY,
    ScenarioEngine,
    ScenarioSpec,
)
from simulator.event_model import EventType
from simulator.security_context import PersistentDeviceContext


def execute(spec, *, seed=151):
    random.seed(seed)
    persistent = PersistentDeviceContext(device_id="device-1")
    event_engine = EventEngine(
        device_id="device-1",
        gateway_id="gateway-1",
        auth_server_id="auth-1",
        persistent_context=persistent,
        start_time=1_000.0,
    )
    return event_engine.execute(spec)


class SynchronizedAnomalyCandidateTests(unittest.TestCase):
    def test_capability_manifest_supports_only_minimum_subset(self):
        self.assertEqual(
            {"nonce_reuse", "timestamp_inconsistency"},
            set(supported_synchronized_variants()),
        )
        report = synchronized_capability_report()
        self.assertFalse(report["canonical_identifiers_assigned"])
        self.assertEqual(
            VariantCapabilityStatus.QUARANTINED_HISTORICAL,
            VARIANT_CAPABILITIES["replay_token"].status,
        )

    def test_nonce_reuse_links_same_material_across_attempts(self):
        spec = ScenarioEngine(seed=5).synchronized_anomaly("nonce_reuse")
        with patch.dict(STEALTH_FRACTION, {"nonce_reuse": 0.0}):
            events, context = execute(spec)

        record = context.injection_records[0]
        source = next(
            event for event in events
            if event.event_id in record["source_evidence_event_ids"]
        )
        reused = next(
            event for event in events if event.injection_id == record["injection_id"]
        )

        self.assertEqual(source.nonce, reused.nonce)
        self.assertEqual(source.nonce, record["source_material_identifier"])
        self.assertEqual(source.nonce, record["injected_value"])
        self.assertNotEqual(source.auth_attempt_id, reused.auth_attempt_id)
        self.assertEqual(source.auth_attempt_id, record["source_auth_attempt_id"])
        self.assertEqual(
            "within_trace_across_authentication_attempts",
            record["declared_history_scope"],
        )
        self.assertEqual(
            ("temporal/freshness consistency", "replay/single-use"),
            record["invariant_families"],
        )
        self.assertTrue(record["transformation_applied"])
        self.assertTrue(record["evidence_check_passed"])
        self.assertTrue(record["observable_violation_candidate"])
        self.assertEqual("nonce_reuse", reused.anomaly_label)
        self.assertTrue(context.observable_anomaly)

    def test_ordinary_renewal_uses_distinct_nonces(self):
        spec = ScenarioEngine(seed=7).normal_with_renewal()
        spec.generation_profile = SYNCHRONIZED_GENERATION_PROFILE
        events, context = execute(spec)
        nonces = [
            event.nonce for event in events
            if event.event_type == EventType.NONCE_RECEIVED
        ]

        self.assertEqual(2, len(nonces))
        self.assertEqual(2, len(set(nonces)))
        self.assertFalse(context.observable_anomaly)
        self.assertFalse(context.injection_records)

    def test_timestamp_inconsistency_preserves_semantic_order_and_provenance(self):
        spec = ScenarioEngine(seed=11).synchronized_anomaly(
            "timestamp_inconsistency"
        )
        with patch.dict(STEALTH_FRACTION, {"timestamp_inconsistency": 0.0}):
            events, context = execute(spec)

        record = context.injection_records[0]
        target = next(
            event for event in events if event.injection_id == record["injection_id"]
        )
        source = next(
            event for event in events
            if event.event_id in record["source_evidence_event_ids"]
        )
        timestamps = [event.timestamp for event in events]

        self.assertTrue(all(a < b for a, b in zip(timestamps, timestamps[1:])))
        self.assertEqual(target.timestamp, record["original_value"])
        self.assertEqual(target.observed_timestamp, record["injected_value"])
        self.assertLess(target.observed_timestamp, source.observed_timestamp)
        self.assertEqual(
            "declared_event_time_after_predecessor",
            target.targeted_temporal_relationship,
        )
        offset = record["injection_parameters"]["offset_s"]
        self.assertAlmostEqual(
            record["original_value"] - record["injected_value"],
            offset,
            places=5,
        )
        self.assertEqual(
            ("temporal/freshness consistency",),
            record["invariant_families"],
        )
        self.assertEqual(
            "candidate_pending_full_executable_validation",
            record["validation_status"],
        )

    def test_stealth_intent_has_no_observable_anomaly_or_injection_record(self):
        spec = ScenarioEngine(seed=13).synchronized_anomaly("nonce_reuse")
        with patch.dict(STEALTH_FRACTION, {"nonce_reuse": 1.0}):
            events, context = execute(spec)

        self.assertTrue(context.attack_scenario_intent)
        self.assertFalse(context.observable_anomaly)
        self.assertFalse(context.observable_violation_candidate)
        self.assertFalse(context.injection_records)
        self.assertTrue(all(event.anomaly_label is None for event in events))
        features = to_feature_df([(events, context)]).iloc[0]
        self.assertEqual(1, features["attack_scenario_intent"])
        self.assertEqual(0, features["is_anomaly"])
        self.assertIn('"observable_anomaly": false', to_json_log([(events, context)]))

    def test_quarantined_variants_cannot_be_requested_as_synchronized(self):
        generator = ScenarioEngine(seed=17)
        quarantined = {
            "replay_token",
            "duplicate_sequence",
            "impersonation",
            "identity_token_mismatch",
            "access_without_auth",
            "abnormal_failure_rate",
            "abnormal_renewal",
        }
        for name in quarantined:
            with self.subTest(name=name), self.assertRaises(ValueError):
                generator.synchronized_anomaly(name)

    def test_synchronized_batch_filters_historical_distribution(self):
        specs = ScenarioEngine(seed=19).synchronized_batch(
            n_normal=0,
            n_attack=20,
            distribution=cfg.simulation.attack_distribution,
        )

        self.assertEqual(20, len(specs))
        self.assertTrue(all(
            spec.anomaly_type in supported_synchronized_variants()
            for spec in specs
        ))
        self.assertTrue(all(
            spec.generation_profile == SYNCHRONIZED_GENERATION_PROFILE
            for spec in specs
        ))

    def test_historical_names_remain_explicit_provenance_not_sync_capability(self):
        historical = ScenarioEngine(seed=23).anomaly("replay_token")

        self.assertEqual("historical-27135bf", historical.generation_profile)
        self.assertEqual("replay_token", historical.scenario_type)
        self.assertNotIn("replay_token", supported_synchronized_variants())

    def test_benign_unusual_paths_do_not_become_anomaly_positive(self):
        generator = ScenarioEngine(seed=29)
        specs = [
            generator.normal_with_retry(),
            generator.normal_with_renewal(),
            ScenarioSpec(
                scenario_id="benign-denial",
                scenario_type="normal",
                is_anomaly=False,
                generation_profile=SYNCHRONIZED_GENERATION_PROFILE,
                normal_steps=[
                    *AUTH_PREFIX,
                    EventType.ACCESS_REQUEST,
                    EventType.ACCESS_DENIED,
                    EventType.RETRY,
                    EventType.ACCESS_GRANTED,
                    EventType.SESSION_CLOSED,
                ],
            ),
        ]
        # Retain direct constants as an additional regression against accidental
        # labeling of the same benign failure/renewal mechanisms.
        self.assertTrue(NORMAL_FLOW_WITH_RETRY)
        self.assertTrue(NORMAL_FLOW_WITH_RENEWAL)

        for index, spec in enumerate(specs):
            with self.subTest(spec=spec.scenario_type):
                spec.generation_profile = SYNCHRONIZED_GENERATION_PROFILE
                events, context = execute(spec, seed=100 + index)
                self.assertFalse(context.attack_scenario_intent)
                self.assertFalse(context.observable_anomaly)
                self.assertTrue(all(event.anomaly_label is None for event in events))


if __name__ == "__main__":
    unittest.main()
