"""Focused C1.4 tests for authoritative generated semantic time."""

import random
import unittest
import uuid
from collections import defaultdict
from unittest.mock import patch

from simulator.config.settings import cfg
from simulator.core.auth_server import AuthServer, MQTTBroker
from simulator.core.device import Device
from simulator.core.gateway import Gateway
from simulator.core.session_driver import SessionDriver
from simulator.engines.event_engine import EventEngine, STEALTH_FRACTION
from simulator.engines.scenario_engine import (
    NORMAL_FLOW,
    NORMAL_FLOW_WITH_RENEWAL,
    NORMAL_FLOW_WITH_RETRY,
    ScenarioEngine,
    ScenarioSpec,
)
from simulator.event_model import AuthState, EventResult, EventType
from simulator.provenance import build_generation_provenance
from simulator.runner import run_simulation
from simulator.security_context import PersistentDeviceContext
from simulator.semantic_time import SEMANTIC_TIME_DOMAIN


def normal_spec(steps):
    return ScenarioSpec(
        scenario_id=str(uuid.uuid4()),
        scenario_type="normal",
        is_anomaly=False,
        normal_steps=list(steps),
    )


def engine(persistent=None, start_time=1_000.0):
    persistent = persistent or PersistentDeviceContext(device_id="device-1")
    return EventEngine(
        device_id=persistent.device_id,
        gateway_id="gateway-1",
        auth_server_id="auth-1",
        persistent_context=persistent,
        start_time=start_time,
    )


class SemanticTimelineTests(unittest.TestCase):
    def setUp(self):
        random.seed(41)

    def test_events_share_one_strictly_monotonic_semantic_timeline(self):
        event_engine = engine()
        events, context = event_engine.execute(normal_spec(NORMAL_FLOW))
        timestamps = [event.timestamp for event in events]

        self.assertTrue(all(a < b for a, b in zip(timestamps, timestamps[1:])))
        self.assertTrue(all(
            event.observed_timestamp == event.timestamp for event in events
        ))
        self.assertEqual(SEMANTIC_TIME_DOMAIN, context.semantic_time_domain)
        self.assertEqual(1_000.0, context.trace_started_at)
        self.assertEqual(timestamps[-1], context.trace_ended_at)

    def test_retry_and_new_attempt_follow_failed_attempt(self):
        events, _context = engine().execute(normal_spec(NORMAL_FLOW_WITH_RETRY))
        failure = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE
        )
        retry = next(event for event in events if event.event_type == EventType.RETRY)
        later_success = next(
            event for event in events
            if event.event_type == EventType.AUTHENTICATION_SUCCESS
        )

        self.assertLess(failure.timestamp, retry.timestamp)
        self.assertLess(retry.timestamp, later_success.timestamp)
        self.assertNotEqual(failure.auth_attempt_id, later_success.auth_attempt_id)

    def test_token_validation_before_configured_expiry_is_valid(self):
        events, context = engine().execute(normal_spec(NORMAL_FLOW[:14]))
        validated = events[-1]

        self.assertEqual(EventType.TOKEN_VALIDATED, validated.event_type)
        self.assertEqual(EventResult.SUCCESS, validated.result)
        self.assertEqual(AuthState.TOKEN_VALIDATED, validated.new_state)
        self.assertLess(context.token_validation_at, context.token_issued_at + cfg.security.token_lifetime_s)
        self.assertEqual(cfg.security.token_lifetime_s, context.token_validity_duration_s)

    def test_token_validation_after_configured_expiry_is_rejected(self):
        def delayed_validation(event_type, _profile):
            if event_type == EventType.TOKEN_VALIDATED:
                return cfg.security.token_lifetime_s + 1.0
            return 0.01

        with patch.object(EventEngine, "_sample_delay", side_effect=delayed_validation):
            events, context = engine().execute(normal_spec(NORMAL_FLOW[:14]))
        validation = events[-1]

        self.assertEqual(EventType.TOKEN_VALIDATED, validation.event_type)
        self.assertEqual(EventResult.FAILURE, validation.result)
        self.assertEqual("token_expired", validation.failure_reason)
        self.assertEqual(AuthState.TOKEN_PRESENTED, validation.new_state)
        self.assertEqual("rejected", context.token_validation_result)
        self.assertFalse(context.token_context_active)

    def test_session_open_precedes_semantic_termination(self):
        events, context = engine().execute(normal_spec(NORMAL_FLOW))
        opened = next(
            event for event in events if event.event_type == EventType.SESSION_OPENED
        )
        closed = next(
            event for event in events if event.event_type == EventType.SESSION_CLOSED
        )

        self.assertLess(opened.timestamp, closed.timestamp)
        self.assertEqual(opened.timestamp, context.protected_session_started_at)
        self.assertEqual(closed.timestamp, context.protected_session_ended_at)

    def test_renewal_request_does_not_refresh_validity_before_issuance(self):
        events, context = engine().execute(normal_spec(NORMAL_FLOW_WITH_RENEWAL))
        token_issues = [
            event for event in events if event.event_type == EventType.TOKEN_ISSUED
        ]
        renewal = next(
            event for event in events if event.event_type == EventType.RENEWAL_REQUEST
        )

        self.assertLess(context.protected_session_started_at, renewal.timestamp)
        self.assertEqual(renewal.timestamp, context.renewal_requested_at)
        self.assertLess(renewal.timestamp, token_issues[-1].timestamp)
        self.assertEqual(token_issues[-1].timestamp, context.renewed_token_issued_at)
        self.assertEqual(
            context.renewed_token_issued_at + cfg.security.token_lifetime_s,
            token_issues[-1].token_expiry,
        )

    def test_sequential_traces_for_one_device_do_not_reset_backwards(self):
        persistent = PersistentDeviceContext(device_id="device-1")
        first_events, _ = engine(persistent).execute(normal_spec(NORMAL_FLOW))
        second_events, second_context = engine(
            persistent, start_time=500.0
        ).execute(normal_spec(NORMAL_FLOW))

        self.assertLess(first_events[-1].timestamp, second_events[0].timestamp)
        self.assertEqual(second_events[-1].timestamp, persistent.semantic_time_cursor)
        self.assertEqual(2, persistent.completed_trace_count)
        self.assertEqual(second_events[-1].timestamp, second_context.trace_ended_at)

    def test_runner_preserves_one_device_chronology_across_selected_traces(self):
        with (
            patch.object(cfg.simulation, "num_devices", 1),
            patch.object(cfg.simulation, "num_gateways", 1),
            patch.object(cfg.simulation, "num_sessions_normal", 3),
            patch.object(cfg.simulation, "num_sessions_attack", 0),
            patch.object(cfg.simulation, "wire_entities", False),
        ):
            sequences = run_simulation()

        for (earlier, _), (later, _) in zip(sequences, sequences[1:]):
            self.assertLess(earlier[-1].timestamp, later[0].timestamp)

    def test_wall_clock_anchor_does_not_change_validity_or_relative_timing(self):
        def generate(wall_time):
            random.seed(73)
            with patch("simulator.engines.event_engine.time.time", return_value=wall_time):
                events, context = engine(start_time=None).execute(
                    normal_spec(NORMAL_FLOW)
                )
            origin = events[0].timestamp
            return (
                [round(event.timestamp - origin, 6) for event in events],
                [event.result for event in events],
                context.token_validation_result,
            )

        self.assertEqual(generate(10.0), generate(10_000_000.0))

    def test_equivalent_seed_and_configuration_reproduce_timing_relationships(self):
        def generate():
            random.seed(101)
            events, _context = engine(start_time=4_000.0).execute(
                normal_spec(NORMAL_FLOW_WITH_RETRY)
            )
            return [
                (event.event_type, event.delay_since_previous_event)
                for event in events
            ]

        self.assertEqual(generate(), generate())

    def test_injected_observed_time_does_not_rewind_semantic_clock(self):
        spec = ScenarioEngine(seed=19).timestamp_inconsistency()
        with patch.dict(STEALTH_FRACTION, {"timestamp_inconsistency": 0.0}):
            events, _context = engine().execute(spec)
        injected = next(event for event in events if event.anomaly_label)
        index = events.index(injected)

        self.assertGreater(injected.timestamp, events[index - 1].timestamp)
        self.assertLess(injected.observed_timestamp, injected.timestamp)
        self.assertEqual("injected_device_timestamp", injected.observed_timestamp_source)
        self.assertEqual(
            "declared_event_time_after_predecessor",
            injected.targeted_temporal_relationship,
        )

    def test_provenance_classifies_temporal_parameters(self):
        temporal = build_generation_provenance(
            cfg,
            run_id="test-run",
            generator_git_commit="test-commit",
        ).temporal_contract

        self.assertEqual(SEMANTIC_TIME_DOMAIN, temporal["semantic_time_domain"])
        self.assertEqual(
            "currently enforced semantic rule",
            temporal["parameters"]["security.token_lifetime_s"]["status"],
        )
        self.assertEqual(
            "annotation only",
            temporal["parameters"]["temporal.nonce_lifetime_s"]["status"],
        )
        self.assertEqual(
            "unresolved semantic dependency",
            temporal["parameters"]["security.replay_window_s"]["status"],
        )
        self.assertEqual(
            "inconsistent/conflicting",
            temporal["parameters"]["legacy_temporal_engine_replay_window_s"]["status"],
        )
        self.assertEqual(
            "unused/dead",
            temporal["parameters"]["attack.configured_replay_token_age_range_s"]["status"],
        )

    def test_wired_side_effects_consume_semantic_time(self):
        device = Device.create(index=0)
        gateway = Gateway(gateway_id="gateway-1")
        auth_server = AuthServer(server_id="auth-1")
        broker = MQTTBroker(broker_id="broker-1")
        driver = SessionDriver(
            device=device,
            gateway=gateway,
            auth_server=auth_server,
            broker=broker,
            stats=defaultdict(int),
        )
        persistent = PersistentDeviceContext(device_id=device.device_id)
        event_engine = EventEngine(
            device_id=device.device_id,
            gateway_id="gateway-1",
            auth_server_id="auth-1",
            broker_id="broker-1",
            driver=driver,
            persistent_context=persistent,
            start_time=8_000.0,
        )

        with (
            patch("simulator.core.auth_server.time.time", return_value=-10.0),
            patch("simulator.core.gateway.time.time", return_value=-20.0),
        ):
            events, _context = event_engine.execute(normal_spec(NORMAL_FLOW[:15]))

        issued = next(
            event for event in events if event.event_type == EventType.TOKEN_ISSUED
        )
        opened = next(
            event for event in events if event.event_type == EventType.SESSION_OPENED
        )
        token = auth_server.get_token(issued.token_id)
        broker_session = broker.get_session(device.device_id)

        self.assertEqual(issued.timestamp, token.issued_at)
        self.assertEqual(opened.timestamp, broker_session["connected_at"])
        self.assertGreater(token.issued_at, 8_000.0)

if __name__ == "__main__":
    unittest.main()
