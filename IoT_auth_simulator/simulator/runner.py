"""
simulator/runner.py
────────────────────
Orchestrator: creates devices, runs normal and attack sessions,
and returns the full list of labelled event dicts.
"""

import random
import uuid
from typing import List, Dict, Any, Callable

from tqdm import tqdm

from config.settings import cfg
from simulator.core.device import Device
from simulator.core.gateway import Gateway
from simulator.core.auth_server import AuthServer, MQTTBroker
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

    # Create gateway pool (small building / office)
    gateways = [Gateway(gateway_id=str(uuid.uuid4())[:8]) for _ in range(cfg.simulation.num_gateways)]

    # Shared central services (single auth server + broker for the building)
    auth_server = AuthServer(server_id="auth-01")
    broker      = MQTTBroker(broker_id="broker-01")

    # Device pool and mapping to gateways (round-robin assignment)
    devices: List[Device] = []
    device_gateway_map: Dict[str, Gateway] = {}
    for i in range(cfg.simulation.num_devices):
        dev = Device.create(index=i)
        gw  = gateways[i % len(gateways)]
        devices.append(dev)
        device_gateway_map[dev.device_id] = gw

    events: List[Dict[str, Any]] = []

    total = cfg.simulation.num_sessions_normal + cfg.simulation.num_sessions_attack

    # ── Normal sessions ────────────────────────────────────────────────────────
    for i in range(cfg.simulation.num_sessions_normal):
        device = random.choice(devices)
        gw = device_gateway_map[device.device_id]
        event  = _run_normal_session(device, gw, auth_server, broker)
        events.append(event)

        if progress_callback:
            progress_callback(i + 1, total, f"Normal session {i+1}/{cfg.simulation.num_sessions_normal}")

    # ── Attack sessions ────────────────────────────────────────────────────────
    attack_counts = _compute_attack_counts()
    offset        = cfg.simulation.num_sessions_normal

    # Pre-capture tokens for replay attacks — keep gateway where token was captured
    captured_tokens = _capture_tokens_for_replay(
        attack_counts["replay"], devices, device_gateway_map, auth_server, broker
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

        # Decide infra: reuse victim/gateway for replay & impersonation
        # Create fresh infra only for DoS attacks to avoid polluting shared state with heavy traffic.
        if attack_type == "dos_flooding":
            atk_gateway     = Gateway(gateway_id=str(uuid.uuid4())[:8])
            atk_auth_server = AuthServer(server_id="auth-atk")
            atk_broker      = MQTTBroker(broker_id="broker-atk")
            gw = atk_gateway
            auth_srv = atk_auth_server
            br = atk_broker
        else:
            # For replay/impersonation reuse the gateway of the victim or a random device
            auth_srv = auth_server
            br = broker

        if attack_type == "replay":
            # captured_tokens contains (token_str, gateway)
            if not captured_tokens:
                token_str, gw = "", random.choice(gateways)
            else:
                token_str, gw = captured_tokens[token_idx % len(captured_tokens)]
                token_idx += 1

            # Register attacker in the chosen auth server so enrollment works
            auth_srv._registry[attacker.device_id] = attacker.get_psk_hash()
            event = replay.run(attacker, gw, auth_srv, br, token_str)

        elif attack_type == "impersonation":
            victim = random.choice(victim_devices)
            gw = device_gateway_map[victim.device_id]
            # Choose randomly between stolen and forged credentials
            use_stolen = random.random() < 0.5
            stolen_psk = victim.get_psk_hash() if use_stolen else None
            auth_srv._registry[victim.device_id] = victim.get_psk_hash()
            event = impersonation.run(
                attacker, gw, auth_srv, br,
                victim_device_id=victim.device_id,
                stolen_psk_hash=stolen_psk,
            )

        else:  # dos_flooding
            strategy = random.choice(["auth_flood", "mqtt_flood"])
            auth_srv._registry[attacker.device_id] = attacker.get_psk_hash()
            event = dos_flooding.run(attacker, gw, auth_srv, br, strategy)

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
    step_events = []
    step_events.append(step1_discovery.run(device, gateway))
    step_events.append(step2_pairing.run(device, gateway))

    e3 = step3_enrollment.run(device, gateway, auth_server)
    step_events.append(e3)

    if not e3["step_success"]:
        # Enrollment failed — pad remaining steps with neutral values
        step_events += _pad_failed_steps(device)
        row = build(step_events)
        return label_normal(row)

    e4, token = step4_authorization.run(device, gateway, auth_server)
    step_events.append(e4)

    if not token:
        step_events += _pad_failed_steps(device, from_step=5)
        row = build(step_events)
        return label_normal(row)

    step_events.append(step5_mqtt_session.run(device, gateway, auth_server, broker, token))
    step_events.append(step6_reauth.run(device, gateway, auth_server, token))

    row = build(step_events)
    return label_normal(row)


# ── Helpers ───────────────────────────────────────────────────────────────────

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
    device_gateway_map: Dict[str, Gateway],
    auth_server: AuthServer,
    broker:      MQTTBroker,
) -> List[tuple]:
    """Run n legitimate sessions and collect their tokens for replay attacks.

    Returns a list of (token_str, gateway) tuples so replay attacks present the token
    to the same gateway where it was originally observed.
    """
    tokens = []
    for i in range(n):
        device = devices[i % len(devices)]
        gw = device_gateway_map[device.device_id]
        token_str = replay.capture_token(device, gw, auth_server, broker)
        if token_str:
            tokens.append((token_str, gw))
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