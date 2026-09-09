"""C1.7R regressions for deterministic synchronized generator coherence."""

import random
import unittest
from unittest.mock import patch

from simulator.anomaly_contract import SYNCHRONIZED_GENERATION_PROFILE
from simulator.config.settings import cfg
from simulator.data.dataset_contract import dataset_capability_manifest, field_manifest
from simulator.engines.event_engine import EventEngine
from simulator.engines.scenario_engine import (
    AUTH_PREFIX,
    NORMAL_FLOW_WITH_RENEWAL,
    NORMAL_FLOW_WITH_RETRY,
    ScenarioSpec,
)
from simulator.event_model import AuthState, EventResult, EventType
from simulator.provenance import build_generation_provenance
from simulator.security_context import AuthenticationResult, PersistentDeviceContext
from simulator.validation import validate_synchronized_dataset


def synchronized_spec(steps, scenario_id):
    return ScenarioSpec(
        scenario_id=scenario_id,
        scenario_type="normal",
        is_anomaly=False,
        generation_profile=SYNCHRONIZED_GENERATION_PROFILE,
        normal_steps=list(steps),
    )


def execute(steps, *, scenario_id, seed=1701):
    random.seed(seed)
    engine = EventEngine(
        device_id=f"device-{scenario_id}",
        gateway_id="gateway-c1.7r",
        auth_server_id="auth-c1.7r",
        start_time=30_000.0,
        persistent_context=PersistentDeviceContext(
            device_id=f"device-{scenario_id}"
        ),
    )
    events, context = engine.execute(synchronized_spec(steps, scenario_id))
    return engine, events, context


def validate(events, context):
    provenance = build_generation_provenance(
        cfg,
        run_id="c1.7r-regression",
        generator_git_commit="c1.7r-test",
    )
    return validate_synchronized_dataset(
        [(events, context)],
        provenance=provenance,
        field_manifest=field_manifest(),
        dataset_manifest=dataset_capability_manifest(
            provenance,
            generation_profiles=(context.generation_profile,),
        ),
    )


class SynchronizedGeneratorRepairTests(unittest.TestCase):
    def test_denied_request_cannot_succeed_and_retry_uses_new_request(self):
        steps = [
            *AUTH_PREFIX,
            EventType.ACCESS_REQUEST,
            EventType.ACCESS_DENIED,
            EventType.RETRY,
            EventType.ACCESS_GRANTED,
            EventType.SESSION_CLOSED,
        ]
        # Before C1.7R this forces the first ACCESS_REQUEST to fail randomly,
        # after which ACCESS_DENIED carries not_evaluated/not_executed evidence.
        with patch("simulator.engines.event_engine.random.random", return_value=0.0):
            _engine, events, context = execute(
                steps, scenario_id="denial-repair"
            )

        denied = next(event for event in events if event.event_type == EventType.ACCESS_DENIED)
        granted = next(event for event in events if event.event_type == EventType.ACCESS_GRANTED)
        self.assertEqual(EventResult.FAILURE, denied.result)
        self.assertEqual(AuthState.ACCESS_DENIED, denied.new_state)
        self.assertEqual("denied", denied.authorization_decision)
        self.assertEqual("denied", denied.resource_operation_outcome)
        self.assertNotEqual(denied.access_request_id, granted.access_request_id)
        self.assertEqual("granted", granted.authorization_decision)
        self.assertEqual("success", granted.resource_operation_outcome)
        self.assertTrue(validate(events, context).build_gate_passed)

    def test_failed_current_renewal_attempt_cannot_issue_a_token(self):
        second_token_index = max(
            index
            for index, event_type in enumerate(NORMAL_FLOW_WITH_RENEWAL)
            if event_type == EventType.TOKEN_ISSUED
        )
        steps = NORMAL_FLOW_WITH_RENEWAL[:second_token_index + 1]
        original_outcome = EventEngine._outcome
        authentication_success_count = 0

        def fail_second_authentication(event_type, is_anomaly):
            nonlocal authentication_success_count
            if event_type == EventType.AUTHENTICATION_SUCCESS:
                authentication_success_count += 1
                if authentication_success_count == 2:
                    return EventResult.FAILURE, "forced_failed_renewal_authentication"
            return original_outcome(event_type, is_anomaly)

        with patch.object(EventEngine, "_outcome", side_effect=fail_second_authentication):
            engine, events, context = execute(
                steps, scenario_id="renewal-attempt-repair"
            )

        token_events = [event for event in events if event.event_type == EventType.TOKEN_ISSUED]
        failed_auth = [
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_SUCCESS
            and event.result is EventResult.FAILURE
        ][0]
        attempted_renewal = token_events[-1]
        security = engine.last_authentication_context

        self.assertEqual(EventResult.FAILURE, attempted_renewal.result)
        self.assertEqual("authentication_not_established", attempted_renewal.failure_reason)
        self.assertEqual(failed_auth.auth_attempt_id, attempted_renewal.auth_attempt_id)
        self.assertEqual(token_events[0].token_id, security.token_id)
        self.assertIsNone(security.renewed_token_issued_at)
        self.assertEqual(
            AuthenticationResult.FAILURE,
            security.current_auth_attempt_result,
        )
        self.assertTrue(validate(events, context).build_gate_passed)

    def test_explicit_authentication_failure_has_coherent_state_and_retry(self):
        # Before C1.7R a forced transient RESPONSE_SENT failure left the FSM in
        # CHALLENGE_ISSUED, so the following semantic failure could not reach
        # AUTH_FAILED and the retry could not start a distinct valid attempt.
        with patch("simulator.engines.event_engine.random.random", return_value=0.0):
            _engine, events, context = execute(
                NORMAL_FLOW_WITH_RETRY,
                scenario_id="authentication-failure-repair",
            )

        failure = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE
        )
        success = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_SUCCESS
        )
        self.assertEqual(EventResult.FAILURE, failure.result)
        self.assertEqual(AuthState.AUTH_FAILED, failure.new_state)
        self.assertFalse(failure.authenticated_context_active)
        self.assertNotEqual(failure.auth_attempt_id, success.auth_attempt_id)
        self.assertEqual(EventResult.SUCCESS, success.result)
        self.assertTrue(validate(events, context).build_gate_passed)


if __name__ == "__main__":
    unittest.main()
