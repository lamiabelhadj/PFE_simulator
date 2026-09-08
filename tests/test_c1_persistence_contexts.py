"""Focused C1.2 tests for persistence scope and identifier meaning."""

import json
import random
import unittest
import uuid

from simulator.engines.event_engine import EventEngine
from simulator.data.output_views import to_event_df, to_feature_df, to_json_log
from simulator.engines.scenario_engine import (
    NORMAL_FLOW,
    NORMAL_FLOW_WITH_RENEWAL,
    NORMAL_FLOW_WITH_RETRY,
    REGISTRATION_PHASE,
    ScenarioSpec,
)
from simulator.event_model import AuthState, EventType
from simulator.security_context import PersistentDeviceContext
from simulator.semantic_mapping import IDENTIFIER_SEMANTICS


def normal_spec(steps, name="normal"):
    return ScenarioSpec(
        scenario_id=str(uuid.uuid4()),
        scenario_type=name,
        is_anomaly=False,
        normal_steps=list(steps),
    )


class PersistenceContextTests(unittest.TestCase):
    def setUp(self):
        random.seed(17)
        self.persistent = PersistentDeviceContext(
            device_id="device-1",
            bootstrap_credential_reference="psk-hash-1",
            device_profile_id="sensor",
        )
        self.engine = EventEngine(
            device_id="device-1",
            gateway_id="gateway-1",
            auth_server_id="auth-1",
            start_time=1_000.0,
            persistent_context=self.persistent,
        )

    def test_enrollment_survives_session_close_disconnect_and_timeout(self):
        for ending in (
            EventType.SESSION_CLOSED,
            EventType.DISCONNECT,
            EventType.TIMEOUT,
        ):
            with self.subTest(ending=ending.value):
                persistent = PersistentDeviceContext(
                    device_id=f"device-{ending.value}",
                    bootstrap_credential_reference="stable-bootstrap-binding",
                )
                engine = EventEngine(
                    device_id=persistent.device_id,
                    gateway_id="gateway-1",
                    auth_server_id="auth-1",
                    start_time=1_000.0,
                    persistent_context=persistent,
                )
                # TIMEOUT is valid from SESSION_OPEN; close/disconnect are valid
                # after the representative access grant.
                prefix_length = 15 if ending == EventType.TIMEOUT else 17
                steps = list(NORMAL_FLOW[:prefix_length]) + [ending]
                _events, context = engine.execute(normal_spec(steps))

                self.assertTrue(persistent.enrolled)
                self.assertTrue(persistent.paired)
                self.assertEqual(
                    "stable-bootstrap-binding",
                    persistent.bootstrap_credential_reference,
                )
                self.assertFalse(engine.last_authentication_context.protected_session_active)
                self.assertTrue(engine.last_authentication_context.terminated)
                self.assertTrue(context.persistent_enrolled)

    def test_later_session_starts_from_retained_enrollment(self):
        first_events, first_context = self.engine.execute(normal_spec(NORMAL_FLOW))
        second_events, second_context = self.engine.execute(normal_spec(NORMAL_FLOW))

        self.assertEqual(EventType.DISCOVERY, first_events[0].event_type)
        self.assertEqual(EventType.AUTHENTICATION_REQUEST, second_events[0].event_type)
        self.assertEqual(AuthState.ENROLLED, second_events[0].previous_state)
        self.assertFalse(any(
            event.event_type in REGISTRATION_PHASE for event in second_events
        ))
        self.assertEqual(first_events[0].device_id, second_events[0].device_id)
        self.assertNotEqual(first_context.trace_id, second_context.trace_id)
        self.assertTrue(self.persistent.enrolled)

    def test_retry_uses_distinct_attempts_without_resetting_enrollment(self):
        events, context = self.engine.execute(normal_spec(NORMAL_FLOW_WITH_RETRY))
        failure = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE
        )
        challenges = [
            event for event in events if event.event_type == EventType.CHALLENGE_SENT
        ]

        self.assertEqual(2, len(context.auth_attempt_ids))
        self.assertEqual(failure.auth_attempt_id, challenges[0].auth_attempt_id)
        self.assertNotEqual(challenges[0].auth_attempt_id, challenges[1].auth_attempt_id)
        self.assertTrue(self.persistent.enrolled)

    def test_timeout_can_be_followed_by_a_distinct_authentication_attempt(self):
        steps = [
            *REGISTRATION_PHASE,
            EventType.AUTHENTICATION_REQUEST,
            EventType.TIMEOUT,
            EventType.AUTHENTICATION_REQUEST,
            EventType.CHALLENGE_SENT,
        ]
        events, context = self.engine.execute(normal_spec(steps))
        requests = [
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_REQUEST
        ]

        self.assertEqual(2, len(context.auth_attempt_ids))
        self.assertNotEqual(requests[0].auth_attempt_id, requests[1].auth_attempt_id)
        self.assertFalse(self.engine.last_authentication_context.terminated)
        self.assertTrue(self.persistent.enrolled)

    def test_access_retry_does_not_create_an_authentication_attempt(self):
        steps = [
            *NORMAL_FLOW[:17],
            EventType.ACCESS_REQUEST,
            EventType.ACCESS_DENIED,
            EventType.RETRY,
            EventType.ACCESS_GRANTED,
            EventType.SESSION_CLOSED,
        ]
        _events, context = self.engine.execute(normal_spec(steps))

        self.assertEqual(1, len(context.auth_attempt_ids))

    def test_renewal_attempt_links_to_continuing_protected_session(self):
        events, context = self.engine.execute(normal_spec(NORMAL_FLOW_WITH_RENEWAL))
        opened = next(
            event for event in events if event.event_type == EventType.SESSION_OPENED
        )
        renewal = next(
            event for event in events if event.event_type == EventType.RENEWAL_REQUEST
        )

        self.assertEqual(2, len(context.auth_attempt_ids))
        self.assertEqual((renewal.auth_attempt_id,), context.renewal_auth_attempt_ids)
        self.assertEqual(opened.protected_session_id, renewal.protected_session_id)
        self.assertEqual(
            renewal.protected_session_id,
            context.refreshes_protected_session_id,
        )

    def test_identifiers_have_separate_scopes_and_legacy_id_is_explicit(self):
        events, context = self.engine.execute(normal_spec(NORMAL_FLOW))
        first = events[0]
        opened_index = next(
            i for i, event in enumerate(events)
            if event.event_type == EventType.SESSION_OPENED
        )

        self.assertEqual("device-1", context.device_id)
        self.assertEqual(first.trace_id, context.trace_id)
        self.assertEqual(first.scenario_id, context.scenario_id)
        self.assertEqual(first.session_id, context.legacy_session_id)
        self.assertNotEqual(first.trace_id, first.scenario_id)
        self.assertNotEqual(first.trace_id, first.session_id)
        self.assertTrue(all(
            event.protected_session_id is None for event in events[:opened_index]
        ))
        self.assertTrue(all(
            event.protected_session_id == context.protected_session_id
            for event in events[opened_index:]
        ))
        self.assertEqual("legacy alias", IDENTIFIER_SEMANTICS["session_id"]["status"])

        event_df = to_event_df([(events, context)])
        feature_df = to_feature_df([(events, context)])
        nested = json.loads(to_json_log([(events, context)]))[0]
        self.assertTrue({
            "trace_id", "auth_attempt_id", "protected_session_id"
        }.issubset(event_df.columns))
        self.assertTrue({
            "trace_id", "protected_session_id", "auth_attempt_count"
        }.issubset(feature_df.columns))
        self.assertEqual(context.trace_id, nested["trace_id"])
        self.assertEqual(context.legacy_session_id, nested["legacy_session_id"])

    def test_registered_establishes_no_condition_beyond_enrolled(self):
        self.persistent.record_successful_event(
            EventType.REGISTRATION_REQUEST,
            AuthState.REGISTERED,
        )

        self.assertTrue(self.persistent.enrolled)
        self.assertEqual(AuthState.ENROLLED, self.persistent.legacy_auth_state())

    def test_context_rejects_a_different_device_identity(self):
        with self.assertRaises(ValueError):
            EventEngine(
                device_id="other-device",
                gateway_id="gateway-1",
                auth_server_id="auth-1",
                persistent_context=self.persistent,
            )

    def test_persistent_blocking_is_not_reset_to_unregistered(self):
        blocked = PersistentDeviceContext(device_id="blocked-device", blocked=True)
        engine = EventEngine(
            device_id="blocked-device",
            gateway_id="gateway-1",
            auth_server_id="auth-1",
            persistent_context=blocked,
        )

        initial, _steps, _position = engine._execution_plan(normal_spec(NORMAL_FLOW))

        self.assertEqual(AuthState.BLOCKED, initial)
        self.assertTrue(blocked.blocked)


if __name__ == "__main__":
    unittest.main()
