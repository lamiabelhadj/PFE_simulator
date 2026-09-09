"""C1.6 tests for synchronized dataset information boundaries."""

import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.anomaly_contract import SYNCHRONIZED_GENERATION_PROFILE
from simulator.config.settings import cfg
from simulator.data.dataset_contract import (
    Availability,
    FieldRole,
    SYNCHRONIZED_FIELD_DEFINITIONS,
    field_manifest,
    field_names_for_view,
    historical_feature_contract,
)
from simulator.data.output_views import to_feature_df
from simulator.data.synchronized_views import (
    SynchronizedOutputViews,
    build_synchronized_bundle,
    legacy_contract_for_sequences,
    to_detector_observation_df,
)
from simulator.data import exporter
from simulator.engines.event_engine import EventEngine, STEALTH_FRACTION
from simulator.engines.scenario_engine import ScenarioEngine
from simulator.provenance import build_generation_provenance
from simulator.security_context import PersistentDeviceContext


def execute(spec, *, seed=601):
    random.seed(seed)
    return EventEngine(
        device_id="device-1",
        gateway_id="gateway-1",
        auth_server_id="auth-1",
        broker_id="broker-1",
        persistent_context=PersistentDeviceContext(device_id="device-1"),
        start_time=10_000.0,
    ).execute(spec)


class DatasetInformationBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        generator = ScenarioEngine(seed=61)
        normal = generator.normal()
        normal.generation_profile = SYNCHRONIZED_GENERATION_PROFILE
        nonce = generator.synchronized_anomaly("nonce_reuse")
        timestamp = generator.synchronized_anomaly("timestamp_inconsistency")
        with patch.dict(STEALTH_FRACTION, {
            "nonce_reuse": 0.0,
            "timestamp_inconsistency": 0.0,
        }):
            cls.sequences = [
                execute(normal, seed=611),
                execute(nonce, seed=612),
                execute(timestamp, seed=613),
            ]
        cls.provenance = build_generation_provenance(
            cfg, run_id="run-c1.6", generator_git_commit="test-commit"
        )
        cls.bundle = build_synchronized_bundle(
            cls.sequences, provenance=cls.provenance
        )

    def test_every_synchronized_exported_field_has_exactly_one_definition(self):
        fields_by_view = {}
        for definition in SYNCHRONIZED_FIELD_DEFINITIONS:
            key = (definition.export_view, definition.field_name)
            self.assertNotIn(key, fields_by_view)
            fields_by_view[key] = definition

        actual = {
            "detector_observations": set(self.bundle["detector_observations"][0]),
            "ground_truth_events": set(self.bundle["ground_truth"]["events"][0]),
            "ground_truth_traces": set(self.bundle["ground_truth"]["traces"][0]),
            "provenance_dataset": set(self.bundle["provenance"]["dataset"]),
            "provenance_traces": set(self.bundle["provenance"]["traces"][0]),
            "provenance_events": set(self.bundle["provenance"]["events"][0]),
            "debug_events": set(self.bundle["debug"]["events"][0]),
            "debug_traces": set(self.bundle["debug"]["traces"][0]),
        }
        for view, names in actual.items():
            self.assertEqual(names, set(field_names_for_view(view)), view)

    def test_observation_roles_and_availability_are_complete(self):
        definitions = [
            item for item in SYNCHRONIZED_FIELD_DEFINITIONS
            if item.export_view == "detector_observations"
        ]
        self.assertTrue(definitions)
        self.assertTrue(all(
            item.role in {FieldRole.OBSERVABLE, FieldRole.DERIVED_OBSERVABLE}
            for item in definitions
        ))
        self.assertTrue(all(item.availability is Availability.EVENT_TIME for item in definitions))
        self.assertTrue(all(item.detector_feature_default for item in definitions))

    def test_gt_provenance_debug_and_identifiers_are_isolated(self):
        observations = set(self.bundle["detector_observations"][0])
        forbidden = {
            "anomaly_label", "attack_type", "anomaly_variant_name",
            "attack_phase", "severity", "injection_id", "invariant_families",
            "observable_anomaly", "observable_violation_candidate",
            "attack_scenario_intent", "scenario_intent", "source_context",
            "timestamp", "semantic_timestamp", "observed_timestamp_source",
            "targeted_temporal_relationship", "previous_state", "new_state",
            "authenticated_identity", "token_validation_result",
            "authorization_decision", "resource_operation_outcome",
            "authenticated_context_active", "token_context_active",
            "protected_session_active", "trust_score", "gateway_decision",
            "device_id", "trace_id", "scenario_id", "auth_attempt_id",
            "protected_session_id", "session_id", "legacy_session_id", "run_id",
        }
        self.assertFalse(observations & forbidden)

    def test_timestamp_candidate_exposes_only_observed_temporal_evidence(self):
        timestamp_events, timestamp_context = self.sequences[2]
        rows = to_detector_observation_df([(timestamp_events, timestamp_context)])
        target_event = next(event for event in timestamp_events if event.injection_id)
        target_row = rows.iloc[timestamp_events.index(target_event)]

        self.assertAlmostEqual(
            target_event.observed_timestamp, target_row["observed_timestamp"], places=6
        )
        self.assertNotEqual(target_event.timestamp, target_row["observed_timestamp"])
        self.assertNotIn("semantic_timestamp", rows.columns)
        self.assertNotIn("injection_id", rows.columns)
        self.assertNotIn("timestamp_delta_s", rows.columns)

    def test_nonce_candidate_exposes_material_not_convenience_answer(self):
        nonce_events, nonce_context = self.sequences[1]
        rows = to_detector_observation_df([(nonce_events, nonce_context)])
        nonces = [value for value in rows["nonce"].dropna().tolist()]

        self.assertGreater(len(nonces), len(set(nonces)))
        self.assertNotIn("nonce_reused", rows.columns)
        self.assertNotIn("n_nonce_reuses", rows.columns)
        self.assertNotIn("source_evidence_event_ids", rows.columns)
        self.assertNotIn("injection_id", rows.columns)

    def test_identifiers_remain_available_for_grouping_in_provenance(self):
        trace = self.bundle["provenance"]["traces"][0]
        self.assertEqual("run-c1.6", trace["run_id"])
        for name in (
            "device_id", "trace_id", "scenario_id", "auth_attempt_ids",
            "protected_session_id", "legacy_session_id",
        ):
            self.assertIn(name, trace)
        self.assertNotIn("device_id", self.bundle["detector_observations"][0])

    def test_retrospective_aggregates_are_not_event_time_features(self):
        definition = next(
            item for item in SYNCHRONIZED_FIELD_DEFINITIONS
            if item.field_name == "full_session_aggregates"
        )
        self.assertEqual(Availability.RETROSPECTIVE, definition.availability)
        self.assertTrue(definition.uses_future_information)
        self.assertTrue(definition.requires_session_completion)
        self.assertNotIn("session_duration_s", self.bundle["detector_observations"][0])

    def test_manifests_serialize_and_capabilities_are_truthful(self):
        encoded = json.dumps(self.bundle["field_manifest"])
        loaded = json.loads(encoded)
        self.assertEqual("detector_observations", loaded["default_detector_view"])
        self.assertEqual({item.value for item in FieldRole}, set(loaded["role_vocabulary"]))
        self.assertEqual(
            {item.value for item in Availability},
            set(loaded["availability_vocabulary"]),
        )

        capabilities = self.bundle["provenance"]["dataset"]["capabilities"]
        self.assertEqual(
            ["nonce_reuse", "timestamp_inconsistency"],
            capabilities["supported_synchronized_anomaly_variants"],
        )
        self.assertFalse(capabilities["global_discrete_event_simulation"])
        self.assertFalse(capabilities["operational_trace_support"])
        self.assertFalse(capabilities["full_executable_invariant_validation"])
        json.loads(json.dumps(capabilities))

    def test_historical_feature_builder_is_explicitly_legacy(self):
        historical = to_feature_df(self.sequences)
        contract = legacy_contract_for_sequences(self.sequences)
        self.assertGreater(len(historical.columns), 0)
        self.assertEqual("legacy_mixed_role_not_detector_ready", contract["status"])
        self.assertFalse(contract["detector_ready"])
        self.assertEqual(len(historical.columns), len(contract["migration_metadata"]))
        self.assertEqual(
            "legacy_mixed_role_not_detector_ready",
            historical_feature_contract()["status"],
        )

        historical_spec = ScenarioEngine(seed=67).normal()
        historical_pair = execute(historical_spec, seed=671)
        with self.assertRaisesRegex(ValueError, "historical generation profiles"):
            to_detector_observation_df([historical_pair])

    def test_separated_files_can_be_saved_and_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = SynchronizedOutputViews(directory).save(
                self.sequences, stem="test", provenance=self.provenance
            )
            self.assertEqual(7, len(paths))
            self.assertTrue(all(path.exists() for path in paths.values()))
            manifest = json.loads(Path(paths["field_manifest"]).read_text())
            dataset = json.loads(Path(paths["dataset_manifest"]).read_text())
            self.assertEqual("detector_observations", manifest["default_detector_view"])
            self.assertEqual("run-c1.6", dataset["run_id"])

    def test_default_generator_export_uses_synchronized_not_legacy_surface(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            exporter, "DATA_DIR", Path(directory)
        ):
            primary = exporter.save(self.sequences, filename="test.csv")
            names = {path.name for path in Path(directory).iterdir()}

            self.assertEqual("test_observations.csv", primary.name)
            self.assertIn("test_field_manifest.json", names)
            self.assertIn("test_ground_truth_events.csv", names)
            self.assertNotIn("test_features.csv", names)
if __name__ == "__main__":
    unittest.main()
