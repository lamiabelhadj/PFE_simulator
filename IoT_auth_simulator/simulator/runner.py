"""
simulator/runner.py
────────────────────
Orchestrator: creates devices, runs normal and attack sessions,
and returns the full list of labelled event dicts.
also collects temporal event metadata while preserving flat CSV output.
"""

import random
import time
import uuid
from typing import List, Dict, Any, Callable

from tqdm import tqdm

from config.settings import cfg
from simulator.core.device import Device
from simulator.core.gateway import Gateway
from simulator.core.auth_server import AuthServer, MQTTBroker
from simulator.core.event import AuthenticationEvent
from simulator.flows import (
    step1_discovery, step2_pairing, step3_enrollment,
    step4_authorization, step5_mqtt_session, step6_reauth,
)
from simulator.attacks import replay, impersonation, dos_flooding
from data.feature_builder import build
from data.labeler import label_normal


# ── Public entry point ─────────────────────────────────────────────────────────

def run_simulation(
    progress_callback: Callable[[int, int, str], None] = None,
) -> List[Dict[str, Any]]:
    """
    Run the full simulation and return all labelled session events.

    Returns
    -------
    List of flat event dicts — one per session
    """
    random.seed(cfg.simulation.random_seed)

    # Shared infrastructure (single gateway, auth server, broker)
    gateway     = Gateway(gateway_id=str(uuid.uuid4())[:8])
    auth_server = AuthServer(server_id="auth-01")
    broker      = MQTTBroker(broker_id="broker-01")

    # Device pool
    devices = [
        Device.create(index=i)
        for i in range(cfg.simulation.num_devices)
    ]

    events: List[Dict[str, Any]] = []

    total = cfg.simulation.num_sessions_normal + cfg.simulation.num_sessions_attack

    # ── Normal sessions ────────────────────────────────────────────────────────
    for i in range(cfg.simulation.num_sessions_normal):
        device = random.choice(devices)
        event  = _run_normal_session(device, gateway, auth_server, broker)
        events.append(event)

        if progress_callback:
            progress_callback(i + 1, total, f"Normal session {i+1}/{cfg.simulation.num_sessions_normal}")

    # ── Attack sessions ────────────────────────────────────────────────────────
    attack_counts = _compute_attack_counts()
    offset        = cfg.simulation.num_sessions_normal

    # Pre-capture tokens for replay attacks
    captured_tokens = _capture_tokens_for_replay(
        attack_counts["replay"], devices, gateway, auth_server, broker
    )
    token_idx = 0

    # Victim pool for impersonation
    victim_devices = random.sample(devices, min(20, len(devices)))

    for j in range(cfg.simulation.num_sessions_attack):
        attack_type = _pick_attack_type(j, attack_counts)
        attacker    = Device.create(
            index=cfg.simulation.num_devices + j,
            is_attacker=True,
        )

        # Fresh infra per attack to avoid state bleed
        atk_gateway     = Gateway(gateway_id=str(uuid.uuid4())[:8])
        atk_auth_server = AuthServer(server_id="auth-atk")
        atk_broker      = MQTTBroker(broker_id="broker-atk")

        if attack_type == "replay":
            token_str = captured_tokens[token_idx % len(captured_tokens)] if captured_tokens else ""
            token_idx += 1
            # Register attacker in fresh auth server so enrollment works
            atk_auth_server._registry[attacker.device_id] = attacker.get_psk_hash()
            event = replay.run(attacker, atk_gateway, atk_auth_server, atk_broker, token_str)

        elif attack_type == "impersonation":
            victim = random.choice(victim_devices)
            # Choose randomly between stolen and forged credentials
            use_stolen = random.random() < 0.5
            stolen_psk = victim.get_psk_hash() if use_stolen else None
            atk_auth_server._registry[victim.device_id] = victim.get_psk_hash()
            event = impersonation.run(
                attacker, atk_gateway, atk_auth_server, atk_broker,
                victim_device_id=victim.device_id,
                stolen_psk_hash=stolen_psk,
            )

        else:  # dos_flooding
            strategy = random.choice(["auth_flood", "mqtt_flood"])
            atk_auth_server._registry[attacker.device_id] = attacker.get_psk_hash()
            event = dos_flooding.run(attacker, atk_gateway, atk_auth_server, atk_broker, strategy)

        events.append(event)

        if progress_callback:
            progress_callback(offset + j + 1, total, f"Attack session {j+1}/{cfg.simulation.num_sessions_attack} [{attack_type}]")

    return events


# ── Normal session ─────────────────────────────────────────────────────────────

def _run_normal_session(
    device:      Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
) -> Dict[str, Any]:
    """
    Execute a normal (benign) authentication session and collect both the flat row
    and internal event metadata (events are stored in _internal_events on the row).
    
    Returns the same flat row as before for CSV export compatibility, but enriches
    it with a list of AuthenticationEvent objects for future temporal analysis.
    """
    scenario_id = str(uuid.uuid4())
    session_start_time = time.time() * 1000  # Convert to milliseconds
    
    step_events = []
    events_list = []  # Collect AuthenticationEvent objects
    previous_state = device.state.name
    
    # ── Step 1: Discovery ──────────────────────────────────────────────────────
    t_step_start = time.time() * 1000
    e1 = step1_discovery.run(device, gateway)
    step_events.append(e1)
    
    event1 = AuthenticationEvent(
        scenario_id=scenario_id,
        event_type="discovery",
        timestamp_ms=t_step_start,
        device_id=device.device_id,
        gateway_id=gateway.gateway_id,
        auth_server_id=auth_server.server_id,
        previous_state=previous_state,
        new_state=device.state.name,
        result=bool(e1.get("step_success", 0)),
        latency_ms=e1.get("step_latency_ms", 0.0),
        delay_since_previous_event_ms=0.0,  # First event
        step_output=e1,
    )
    events_list.append(event1)
    previous_state = device.state.name
    
    # ── Step 2: Pairing ────────────────────────────────────────────────────────
    t_step_start = time.time() * 1000
    e2 = step2_pairing.run(device, gateway)
    step_events.append(e2)
    
    delay_since_prev = t_step_start - (event1.timestamp_ms + event1.latency_ms)
    event2 = AuthenticationEvent(
        scenario_id=scenario_id,
        event_type="pairing",
        timestamp_ms=t_step_start,
        device_id=device.device_id,
        gateway_id=gateway.gateway_id,
        auth_server_id=auth_server.server_id,
        previous_state=previous_state,
        new_state=device.state.name,
        result=bool(e2.get("step_success", 0)),
        latency_ms=e2.get("step_latency_ms", 0.0),
        delay_since_previous_event_ms=delay_since_prev,
        step_output=e2,
    )
    events_list.append(event2)
    previous_state = device.state.name

    # ── Step 3: Enrollment ─────────────────────────────────────────────────────
    t_step_start = time.time() * 1000
    e3 = step3_enrollment.run(device, gateway, auth_server)
    step_events.append(e3)
    
    delay_since_prev = t_step_start - (event2.timestamp_ms + event2.latency_ms)
    event3 = AuthenticationEvent(
        scenario_id=scenario_id,
        event_type="enrollment",
        timestamp_ms=t_step_start,
        device_id=device.device_id,
        gateway_id=gateway.gateway_id,
        auth_server_id=auth_server.server_id,
        session_id=scenario_id,  # Session now exists after enrollment
        previous_state=previous_state,
        new_state=device.state.name,
        result=bool(e3.get("step_success", 0)),
        failure_reason="enrollment_failed" if not e3.get("step_success", 0) else None,
        latency_ms=e3.get("step_latency_ms", 0.0),
        delay_since_previous_event_ms=delay_since_prev,
        step_output=e3,
    )
    events_list.append(event3)
    previous_state = device.state.name

    if not e3.get("step_success", 0):
        # Enrollment failed — pad remaining steps
        step_events += _pad_failed_steps(device)
        row = build(step_events)
        row = label_normal(row)
        row["_internal_events"] = events_list  # Attach events for internal use
        return row

    # ── Step 4: Authorization ──────────────────────────────────────────────────
    t_step_start = time.time() * 1000
    e4, token = step4_authorization.run(device, gateway, auth_server)
    step_events.append(e4)
    
    delay_since_prev = t_step_start - (event3.timestamp_ms + event3.latency_ms)
    token_id = str(uuid.uuid4()) if token else None
    event4 = AuthenticationEvent(
        scenario_id=scenario_id,
        event_type="authorization",
        timestamp_ms=t_step_start,
        device_id=device.device_id,
        gateway_id=gateway.gateway_id,
        auth_server_id=auth_server.server_id,
        session_id=scenario_id,
        token_id=token_id,
        previous_state=previous_state,
        new_state=device.state.name,
        result=bool(e4.get("step_success", 0)),
        failure_reason="token_request_failed" if not token else None,
        latency_ms=e4.get("step_latency_ms", 0.0),
        delay_since_previous_event_ms=delay_since_prev,
        step_output=e4,
    )
    events_list.append(event4)
    previous_state = device.state.name

    if not token:
        step_events += _pad_failed_steps(device, from_step=5)
        row = build(step_events)
        row = label_normal(row)
        row["_internal_events"] = events_list
        return row

    # ── Step 5: MQTT Session ───────────────────────────────────────────────────
    t_step_start = time.time() * 1000
    e5 = step5_mqtt_session.run(device, gateway, auth_server, broker, token)
    step_events.append(e5)
    
    delay_since_prev = t_step_start - (event4.timestamp_ms + event4.latency_ms)
    event5 = AuthenticationEvent(
        scenario_id=scenario_id,
        event_type="mqtt_session",
        timestamp_ms=t_step_start,
        device_id=device.device_id,
        gateway_id=gateway.gateway_id,
        auth_server_id=auth_server.server_id,
        session_id=scenario_id,
        token_id=token_id,
        previous_state=previous_state,
        new_state=device.state.name,
        result=bool(e5.get("step_success", 0)),
        latency_ms=e5.get("step_latency_ms", 0.0),
        delay_since_previous_event_ms=delay_since_prev,
        step_output=e5,
    )
    events_list.append(event5)
    previous_state = device.state.name

    # ── Step 6: Re-authentication ──────────────────────────────────────────────
    t_step_start = time.time() * 1000
    e6 = step6_reauth.run(device, gateway, auth_server, token)
    step_events.append(e6)
    
    delay_since_prev = t_step_start - (event5.timestamp_ms + event5.latency_ms)
    event6 = AuthenticationEvent(
        scenario_id=scenario_id,
        event_type="reauth",
        timestamp_ms=t_step_start,
        device_id=device.device_id,
        gateway_id=gateway.gateway_id,
        auth_server_id=auth_server.server_id,
        session_id=scenario_id,
        token_id=token_id,
        previous_state=previous_state,
        new_state=device.state.name,
        result=bool(e6.get("step_success", 0)),
        latency_ms=e6.get("step_latency_ms", 0.0),
        delay_since_previous_event_ms=delay_since_prev,
        step_output=e6,
    )
    events_list.append(event6)
    
    row = build(step_events)
    row = label_normal(row)
    
    # ── Attach internal events for future temporal analysis ────────────────────
    # These are NOT included in the flat CSV but can be used for event-log export
    row["_internal_events"] = events_list

    return row


# ── Helpers ────────────────────────────────────────────────────────────────────

def _compute_attack_counts() -> Dict[str, int]:
    """Split the attack session budget according to the configured distribution."""
    total   = cfg.simulation.num_sessions_attack
    dist    = cfg.simulation.attack_distribution
    counts  = {k: int(v * total) for k, v in dist.items()}
    # Assign any rounding remainder to the first type
    remainder = total - sum(counts.values())
    first_key = next(iter(counts))
    counts[first_key] += remainder
    return counts


def _pick_attack_type(index: int, counts: Dict[str, int]) -> str:
    """Return the attack type for attack session at position `index`."""
    cursor = 0
    for attack_type, count in counts.items():
        cursor += count
        if index < cursor:
            return attack_type
    return list(counts.keys())[-1]


def _capture_tokens_for_replay(
    n:           int,
    devices:     List[Device],
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
) -> List[str]:
    """Run n legitimate sessions and collect their tokens for replay attacks."""
    tokens = []
    for i in range(n):
        device = devices[i % len(devices)]
        token_str = replay.capture_token(device, gateway, auth_server, broker)
        if token_str:
            tokens.append(token_str)
    return tokens


def _pad_failed_steps(device: Device, from_step: int = 4) -> List[Dict]:
    """Return zero-value placeholder dicts for steps that were never reached."""
    pads = []
    step_names = ["authorization", "mqtt_session", "reauth"]
    for name in step_names[from_step - 4:]:
        pads.append({
            "step": name, "step_latency_ms": 0.0, "step_success": 0,
        })
    return pads