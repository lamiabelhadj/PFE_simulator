"""Completeness tests for C1.1 mappings, not behavioral correctness tests."""

import json
import unittest

from simulator.config.settings import cfg
from simulator.core.device import DeviceState
from simulator.event_model import AuthState, EventType
from simulator.provenance import (
    BEHAVIOR_MODEL_VERSION,
    build_generation_provenance,
)
from simulator.semantic_mapping import (
    ANOMALY_NAME_MAPPINGS,
    AUTH_STATE_MAPPINGS,
    DEVICE_STATE_MAPPINGS,
    EVENT_TYPE_MAPPINGS,
    MappingStatus,
    semantic_mapping_report,
)
from simulator.state_machine import ANOMALY_TRANSITIONS


class ProvenanceTests(unittest.TestCase):
    def test_behavior_model_and_run_metadata_are_exposed(self):
        provenance = build_generation_provenance(
            cfg,
            run_id="test-run",
            generator_git_commit="test-commit",
        )

        self.assertEqual("behavioral-model-v1", BEHAVIOR_MODEL_VERSION)
        self.assertEqual(BEHAVIOR_MODEL_VERSION, provenance.behavior_model_version)
        self.assertEqual("test-run", provenance.run_id)
        self.assertEqual("test-commit", provenance.generator_git_commit)
        self.assertTrue(provenance.generator_software_version)
        self.assertTrue(provenance.event_schema_version)
        self.assertTrue(provenance.feature_schema_version)
        self.assertTrue(provenance.configuration_version)
        self.assertTrue(provenance.configuration_snapshot_reference.startswith("sha256:"))
        json.dumps(provenance.to_dict())


class MappingCompletenessTests(unittest.TestCase):
    def test_every_auth_state_is_explicitly_classified(self):
        self.assertEqual(set(AuthState), set(AUTH_STATE_MAPPINGS))

    def test_every_device_state_is_explicitly_classified(self):
        self.assertEqual(set(DeviceState), set(DEVICE_STATE_MAPPINGS))

    def test_every_event_type_is_explicitly_classified(self):
        self.assertEqual(set(EventType), set(EVENT_TYPE_MAPPINGS))

    def test_every_historical_anomaly_name_is_explicitly_classified(self):
        self.assertEqual(set(ANOMALY_TRANSITIONS), set(ANOMALY_NAME_MAPPINGS))

    def test_registered_is_only_a_legacy_alias_for_enrolled(self):
        registered = AUTH_STATE_MAPPINGS[AuthState.REGISTERED]
        enrolled = AUTH_STATE_MAPPINGS[AuthState.ENROLLED]

        self.assertEqual(MappingStatus.LEGACY_ALIAS, registered.status)
        self.assertEqual(enrolled.semantic_concept, registered.semantic_concept)
        self.assertNotEqual(MappingStatus.MAPPED, registered.status)
        self.assertIsNone(registered.semantic_identifier)

    def test_noncanonical_values_are_explicit(self):
        all_entries = (
            list(EVENT_TYPE_MAPPINGS.values())
            + list(AUTH_STATE_MAPPINGS.values())
            + list(DEVICE_STATE_MAPPINGS.values())
            + list(ANOMALY_NAME_MAPPINGS.values())
        )
        noncanonical = {
            MappingStatus.LEGACY_ALIAS,
            MappingStatus.COMPOSITE,
            MappingStatus.IMPLEMENTATION_ONLY,
            MappingStatus.UNRESOLVED,
            MappingStatus.UNSUPPORTED,
        }

        self.assertTrue(any(entry.status in noncanonical for entry in all_entries))
        for entry in all_entries:
            self.assertIsInstance(entry.status, MappingStatus)
            self.assertIsNone(entry.semantic_identifier)

    def test_machine_readable_report_is_complete_and_not_canonicalized(self):
        report = semantic_mapping_report()

        self.assertFalse(report["canonical_identifiers_assigned"])
        self.assertEqual(23, report["implementation_facts"]["auth_state_count"])
        self.assertEqual(10, report["implementation_facts"]["device_state_count"])
        self.assertEqual(28, report["implementation_facts"]["event_type_count"])
        self.assertEqual(53, report["implementation_facts"]["transition_count"])
        self.assertEqual(
            "historical implementation facts only",
            report["implementation_facts"]["vocabulary_authority"],
        )
        json.dumps(report)


if __name__ == "__main__":
    unittest.main()
