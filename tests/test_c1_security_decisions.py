"""Focused C1.3 tests for result/state and access-decision coherence."""

import random
import unittest
import uuid
from unittest.mock import patch

from simulator.data.output_views import to_event_df, to_feature_df
from simulator.engines.event_engine import EventEngine
from simulator.engines.scenario_engine import (
    AUTH_PREFIX,
    NORMAL_FLOW,
    NORMAL_FLOW_WITH_RETRY,
    REGISTRATION_PHASE,
    ScenarioSpec,
)
from simulator.event_model import AuthState, EventResult, EventType
from simulator.security_context import (
    AuthenticationResult,
    AuthenticationSessionContext,
    AuthorizationDecision,
    PersistentDeviceContext,
    ReferenceAuthorizationPolicy,
    ResourceOperationOutcome,
    TokenValidationResult,
)


def normal_spec(steps):
    return ScenarioSpec(
        scenario_id=str(uuid.uuid4()),
        scenario_type="normal",
        is_anomaly=False,
        normal_steps=list(steps),
    )


class SecurityDecisionTests(unittest.TestCase):
    def setUp(self):
        random.seed(23)
        self.persistent = PersistentDeviceContext(
            device_id="device-1",
            bootstrap_credential_reference="psk-hash",
        )
        self.engine = EventEngine(
            device_id="device-1",
            gateway_id="gateway-1",
            auth_server_id="auth-1",
            persistent_context=self.persistent,
            start_time=1_000.0,
        )

    def _force_failure_for(self, target_event):
        original = EventEngine._outcome

        def outcome(event_type, is_anomaly):
            if event_type == target_event:
                return EventResult.FAILURE, "forced_semantic_failure"
            return original(event_type, is_anomaly)

        return patch.object(EventEngine, "_outcome", side_effect=outcome)

    def test_failed_authentication_success_event_cannot_authenticate(self):
        steps = [
            *REGISTRATION_PHASE,
            EventType.AUTHENTICATION_REQUEST,
            EventType.CHALLENGE_SENT,
            EventType.NONCE_RECEIVED,
            EventType.RESPONSE_SENT,
            EventType.AUTHENTICATION_SUCCESS,
            EventType.TOKEN_ISSUED,
            EventType.TOKEN_PRESENTED,
            EventType.TOKEN_VALIDATED,
            EventType.SESSION_OPENED,
        ]
        with self._force_failure_for(EventType.AUTHENTICATION_SUCCESS):
            events, context = self.engine.execute(normal_spec(steps))

        auth_event = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_SUCCESS
        )
        security = self.engine.last_authentication_context
        self.assertEqual(EventResult.FAILURE, auth_event.result)
        self.assertEqual(AuthState.RESPONSE_SENT, auth_event.new_state)
        self.assertEqual(AuthenticationResult.FAILURE, security.authentication_result)
        self.assertIsNone(security.authenticated_identity)
        self.assertFalse(security.authenticated_context_active)
        self.assertFalse(security.token_issued)
        self.assertIsNone(security.protected_session_id)
        self.assertEqual("failure", context.authentication_result_semantic)

    def test_explicit_failure_then_retry_can_authenticate(self):
        events, context = self.engine.execute(normal_spec(NORMAL_FLOW_WITH_RETRY))
        failure = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE
        )
        success = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_SUCCESS
        )
        security = self.engine.last_authentication_context

        self.assertEqual(AuthState.AUTH_FAILED, failure.new_state)
        self.assertNotEqual(failure.auth_attempt_id, success.auth_attempt_id)
        self.assertEqual(EventResult.SUCCESS, success.result)
        self.assertEqual(AuthState.AUTHENTICATED, success.new_state)
        self.assertEqual(AuthenticationResult.SUCCESS, security.authentication_result)
        self.assertIn(success.event_id, security.authentication_success_event_ids)
        self.assertEqual("success", context.authentication_result_semantic)
        self.assertTrue(all(event.anomaly_label is None for event in events))

    def test_authenticated_context_has_successful_event_provenance(self):
        events, _context = self.engine.execute(normal_spec(NORMAL_FLOW))
        security = self.engine.last_authentication_context
        supporting_events = {
            event.event_id for event in events
            if event.event_type == EventType.AUTHENTICATION_SUCCESS
            and event.result == EventResult.SUCCESS
            and event.new_state == AuthState.AUTHENTICATED
        }

        self.assertEqual(AuthenticationResult.SUCCESS, security.authentication_result)
        self.assertTrue(security.authentication_success_event_ids)
        self.assertTrue(set(security.authentication_success_event_ids) <= supporting_events)

    def test_failed_token_operations_do_not_establish_success_context(self):
        targets = (
            EventType.TOKEN_ISSUED,
            EventType.TOKEN_PRESENTED,
            EventType.TOKEN_VALIDATED,
        )
        target_index = {
            EventType.TOKEN_ISSUED: 12,
            EventType.TOKEN_PRESENTED: 13,
            EventType.TOKEN_VALIDATED: 14,
        }
        for target in targets:
            with self.subTest(target=target.value):
                persistent = PersistentDeviceContext(device_id=f"device-{target.value}")
                engine = EventEngine(
                    device_id=persistent.device_id,
                    gateway_id="gateway-1",
                    auth_server_id="auth-1",
                    persistent_context=persistent,
                    start_time=1_000.0,
                )
                with self._force_failure_for(target):
                    events, _context = engine.execute(
                        normal_spec(NORMAL_FLOW[:target_index[target]])
                    )
                failed = next(event for event in events if event.event_type == target)
                security = engine.last_authentication_context

                self.assertEqual(EventResult.FAILURE, failed.result)
                if target == EventType.TOKEN_ISSUED:
                    self.assertFalse(security.token_issued)
                    self.assertIsNone(security.token_id)
                elif target == EventType.TOKEN_PRESENTED:
                    self.assertFalse(security.token_presented)
                else:
                    self.assertNotEqual(
                        TokenValidationResult.VALIDATED,
                        security.token_validation_result,
                    )

    def test_token_rejection_is_not_validation(self):
        steps = [*NORMAL_FLOW[:13], EventType.TOKEN_REJECTED]
        events, context = self.engine.execute(normal_spec(steps))
        rejected = events[-1]
        security = self.engine.last_authentication_context

        self.assertEqual(EventType.TOKEN_REJECTED, rejected.event_type)
        self.assertEqual(EventResult.FAILURE, rejected.result)
        self.assertEqual(AuthState.AUTH_FAILED, rejected.new_state)
        self.assertEqual(TokenValidationResult.REJECTED, security.token_validation_result)
        self.assertFalse(security.token_context_active)
        self.assertFalse(security.protected_session_active)
        self.assertEqual("rejected", context.token_validation_result)

    def test_active_session_alone_does_not_authorize(self):
        context = AuthenticationSessionContext(
            device_id="device-1",
            trace_id="trace-1",
            scenario_id="scenario-1",
            legacy_session_id="legacy-1",
            current_auth_state=AuthState.SESSION_OPEN,
            current_timestamp=1_000.0,
            token_scope="telemetry:read",
            topic="iot/device-/telemetry",
            resource_id="resource://device-/telemetry",
            requested_action="read",
            protected_session_id="protected-1",
            protected_session_active=True,
        )
        request = context.start_access_request()

        decision, reason = ReferenceAuthorizationPolicy.evaluate(context, request)

        self.assertEqual(AuthorizationDecision.DENIED, decision)
        self.assertEqual("no_successful_authentication", reason)

    def test_token_validation_and_session_open_do_not_imply_authorization(self):
        events, context = self.engine.execute(normal_spec(AUTH_PREFIX))
        opened = events[-1]

        self.assertEqual(EventType.SESSION_OPENED, opened.event_type)
        self.assertEqual("validated", opened.token_validation_result)
        self.assertIsNone(opened.authorization_decision)
        self.assertEqual("not_evaluated", context.authorization_decision)
        self.assertEqual(0, context.authorization_result)
        self.assertTrue(self.engine.last_authentication_context.protected_session_active)
        self.assertTrue(context.authenticated_context_active)
        self.assertTrue(context.token_context_active)
        self.assertTrue(context.protected_session_active)

    def test_valid_token_does_not_authorize_an_unscoped_resource(self):
        context = AuthenticationSessionContext(
            device_id="device-1",
            trace_id="trace-1",
            scenario_id="scenario-1",
            legacy_session_id="legacy-1",
            current_auth_state=AuthState.SESSION_OPEN,
            current_timestamp=1_000.0,
            token_scope="telemetry:read",
            topic="iot/device-1/config",
            resource_id="resource://device-1/config",
            requested_action="read",
            protected_session_id="protected-1",
            protected_session_active=True,
            authentication_result=AuthenticationResult.SUCCESS,
            authenticated_identity="device-1",
            authenticated_context_active=True,
            token_id="token-1",
            token_issued=True,
            token_presented=True,
            token_validation_result=TokenValidationResult.VALIDATED,
            token_context_active=True,
        )
        request = context.start_access_request()

        decision, reason = ReferenceAuthorizationPolicy.evaluate(context, request)

        self.assertEqual(AuthorizationDecision.DENIED, decision)
        self.assertEqual("resource_outside_token_scope", reason)

    def test_granted_operation_has_explicit_authorization_grant(self):
        events, context = self.engine.execute(normal_spec(NORMAL_FLOW))
        granted = next(
            event for event in events if event.event_type == EventType.ACCESS_GRANTED
        )

        self.assertEqual(EventResult.SUCCESS, granted.result)
        self.assertEqual("granted", granted.authorization_decision)
        self.assertEqual("success", granted.resource_operation_outcome)
        self.assertIsNotNone(granted.access_request_id)
        self.assertEqual("granted", context.authorization_decision)
        self.assertEqual("success", context.resource_operation_outcome)

        event_df = to_event_df([(events, context)])
        feature_df = to_feature_df([(events, context)])
        self.assertTrue({
            "access_request_id",
            "authenticated_identity",
            "token_validation_result",
            "authorization_decision",
            "resource_operation_outcome",
        }.issubset(event_df.columns))
        self.assertTrue({
            "authentication_result_semantic",
            "token_validation_result",
            "authorization_decision",
            "resource_operation_outcome",
            "access_request_count",
        }.issubset(feature_df.columns))

    def test_denied_operation_is_not_successful_or_anomalous(self):
        steps = [*AUTH_PREFIX, EventType.ACCESS_REQUEST, EventType.ACCESS_DENIED]
        events, context = self.engine.execute(normal_spec(steps))
        denied = events[-1]

        self.assertEqual(EventResult.FAILURE, denied.result)
        self.assertEqual(AuthState.ACCESS_DENIED, denied.new_state)
        self.assertEqual("denied", denied.authorization_decision)
        self.assertEqual("denied", denied.resource_operation_outcome)
        self.assertIsNone(denied.anomaly_label)
        self.assertEqual("denied", context.authorization_decision)
        self.assertEqual("denied", context.resource_operation_outcome)

    def test_denied_then_granted_uses_a_new_request_context(self):
        steps = [
            *AUTH_PREFIX,
            EventType.ACCESS_REQUEST,
            EventType.ACCESS_DENIED,
            EventType.RETRY,
            EventType.ACCESS_GRANTED,
            EventType.SESSION_CLOSED,
        ]
        events, context = self.engine.execute(normal_spec(steps))
        denied = next(event for event in events if event.event_type == EventType.ACCESS_DENIED)
        retried = next(event for event in events if event.event_type == EventType.RETRY)
        granted = next(event for event in events if event.event_type == EventType.ACCESS_GRANTED)

        self.assertNotEqual(denied.access_request_id, granted.access_request_id)
        self.assertEqual(retried.access_request_id, granted.access_request_id)
        self.assertEqual(("denied", "granted"), context.authorization_decisions)
        self.assertEqual(("denied", "success"), context.resource_operation_outcomes)
        self.assertTrue(all(event.anomaly_label is None for event in events))

    def test_termination_clears_active_session_but_not_enrollment(self):
        for ending in (EventType.SESSION_CLOSED, EventType.DISCONNECT, EventType.TIMEOUT):
            with self.subTest(ending=ending.value):
                persistent = PersistentDeviceContext(device_id=f"device-{ending.value}")
                engine = EventEngine(
                    device_id=persistent.device_id,
                    gateway_id="gateway-1",
                    auth_server_id="auth-1",
                    persistent_context=persistent,
                    start_time=1_000.0,
                )
                prefix = NORMAL_FLOW[:15] if ending == EventType.TIMEOUT else NORMAL_FLOW[:17]
                events, _context = engine.execute(normal_spec([*prefix, ending]))

                self.assertTrue(persistent.enrolled)
                self.assertFalse(engine.last_authentication_context.protected_session_active)
                self.assertFalse(events[-1].protected_session_active)
                self.assertFalse(events[-1].authenticated_context_active)
                self.assertFalse(events[-1].token_context_active)
                self.assertEqual(EventResult.SUCCESS, events[-1].result)


if __name__ == "__main__":
    unittest.main()
