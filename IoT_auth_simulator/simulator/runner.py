"""
simulator/runner.py
────────────────────
Orchestrator: generates a mixed batch of normal and anomaly sessions
using ScenarioEngine + EventEngine, and returns the labelled event sequences.

Architecture (Phase 2)
──────────────────────
  ScenarioEngine.batch()  →  List[ScenarioSpec]
  EventEngine.execute()   →  (List[AuthEvent], SessionContext)
  synchronized exporter   →  observations, GT, provenance, debug, validation
"""

import random
import time
import uuid
from collections import defaultdict
from typing import Callable, List, Optional, Tuple

from simulator.config.settings import cfg
from simulator.core.device import Device
from simulator.engines.scenario_engine import ScenarioEngine
from simulator.engines.event_engine import EventEngine, SessionContext
from simulator.event_model import AuthEvent
from simulator.security_context import PersistentDeviceContext


def run_simulation(
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[Tuple[List[AuthEvent], SessionContext]]:
    """
    Run the full simulation.

    Returns
    -------
    List of (events, context) pairs — one per session.
    Each pair contains:
      events  : correlated AuthEvent sequence (variable length)
      context : SessionContext with all session-level features for the feature CSV
    """
    random.seed(cfg.simulation.random_seed)
    # One coordinate anchor per run. It is used only to make exported semantic
    # times human-readable; all ordering and validity use per-device clocks.
    semantic_time_origin = time.time()

    # Build device pool — each device has a stable IP, PSK, and trust score.
    devices = [Device.create(index=i) for i in range(cfg.simulation.num_devices)]
    # One persistent security context per device, shared across every generated
    # trace selected for that device.  Protected-session termination never
    # replaces these objects or their enrollment/bootstrap facts.
    persistent_contexts = {
        device.device_id: PersistentDeviceContext(
            device_id=device.device_id,
            bootstrap_credential_reference=device.get_psk_hash(),
            device_profile_id=device.device_type,
        )
        for device in devices
    }

    # Shared gateway / server / broker identifiers (round-robin by index).
    gateway_ids = [str(uuid.uuid4())[:8] for _ in range(cfg.simulation.num_gateways)]
    auth_server_id = "auth-01"
    broker_id      = "broker-01"

    # ── Phase C: optionally instantiate the real domain entities and drive them
    # through generation (flag-gated via cfg.simulation.wire_entities). ─────────
    wired = getattr(cfg.simulation, "wire_entities", False)
    entities = None
    if wired:
        from simulator.core.gateway import Gateway
        from simulator.core.auth_server import AuthServer, MQTTBroker
        entities = {
            "auth_server": AuthServer(server_id=auth_server_id),
            "broker":      MQTTBroker(broker_id=broker_id),
            "gateways":    {gid: Gateway(gateway_id=gid) for gid in gateway_ids},
            "stats":       defaultdict(int),
        }

    # Build the full scenario batch (normal + attack, shuffled).
    scenario_engine = ScenarioEngine(seed=cfg.simulation.random_seed)
    specs = scenario_engine.synchronized_batch(
        n_normal     = cfg.simulation.num_sessions_normal,
        n_attack     = cfg.simulation.num_sessions_attack,
        distribution = cfg.simulation.attack_distribution,
    )

    total     = len(specs)
    sequences: List[Tuple[List[AuthEvent], SessionContext]] = []

    for i, spec in enumerate(specs):
        device     = random.choice(devices)
        gateway_id = gateway_ids[i % len(gateway_ids)]

        driver = None
        if wired:
            from simulator.core.session_driver import SessionDriver
            driver = SessionDriver(
                device      = device,
                gateway     = entities["gateways"][gateway_id],
                auth_server = entities["auth_server"],
                broker      = entities["broker"],
                stats       = entities["stats"],
            )

        engine = EventEngine(
            device_id        = device.device_id,
            gateway_id       = gateway_id,
            auth_server_id   = auth_server_id,
            broker_id        = broker_id,
            source_ip        = device.ip_address,
            battery_level    = device.battery_level,
            firmware_version = device.firmware_version,
            driver           = driver,
            start_time       = semantic_time_origin,
            persistent_context = persistent_contexts[device.device_id],
        )
        pair = engine.execute(spec)
        sequences.append(pair)

        if progress_callback:
            label = "normal" if not spec.is_anomaly else spec.anomaly_type
            progress_callback(i + 1, total, f"Session {i + 1}/{total} [{label}]")

    if wired:
        _print_entity_summary(entities)

    return sequences


def _print_entity_summary(entities: dict) -> None:
    """Report the aggregate activity of the real domain entities after a wired run."""
    st  = entities["stats"]
    a   = entities["auth_server"]
    b   = entities["broker"]
    gws = entities["gateways"]
    total_gw_sessions = sum(len(g.sessions) for g in gws.values())
    total_nonces      = sum(len(g._nonce_cache) for g in gws.values())
    print("  ── Domain entities exercised (wire_entities=on) ──")
    print(f"    ECDH exchanges     : {st['ecdh_exchanges']:,}")
    print(f"    Enrollments        : {a.total_enrollments:,}")
    print(f"    Tokens issued      : {a.total_tokens_issued:,}")
    print(f"    Broker CONNECTs    : {b.total_connects:,}")
    print(f"    Broker PUBLISHes   : {b.total_publishes:,}")
    print(f"    Gateway sessions   : {total_gw_sessions:,}")
    print(f"    Nonces cached      : {total_nonces:,}")
