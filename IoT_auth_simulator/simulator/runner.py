"""
simulator/runner.py
────────────────────
Orchestrator: generates a mixed batch of normal and anomaly sessions
using ScenarioEngine + EventEngine, and returns the labelled event sequences.

Architecture (Phase 2)
──────────────────────
  ScenarioEngine.batch()  →  List[ScenarioSpec]
  EventEngine.execute()   →  (List[AuthEvent], SessionContext)
  OutputViews / exporter  →  JSON log, event CSV, feature CSV
"""

import random
import uuid
from typing import Callable, List, Optional, Tuple

from simulator.config.settings import cfg
from simulator.core.device import Device
from simulator.engines.scenario_engine import ScenarioEngine
from simulator.engines.event_engine import EventEngine, SessionContext
from simulator.event_model import AuthEvent


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

    # Build device pool — each device has a stable IP, PSK, and trust score.
    devices = [Device.create(index=i) for i in range(cfg.simulation.num_devices)]

    # Shared gateway / server / broker identifiers (round-robin by index).
    gateway_ids = [str(uuid.uuid4())[:8] for _ in range(cfg.simulation.num_gateways)]
    auth_server_id = "auth-01"
    broker_id      = "broker-01"

    # Build the full scenario batch (normal + attack, shuffled).
    scenario_engine = ScenarioEngine(seed=cfg.simulation.random_seed)
    specs = scenario_engine.batch(
        n_normal     = cfg.simulation.num_sessions_normal,
        n_attack     = cfg.simulation.num_sessions_attack,
        distribution = cfg.simulation.attack_distribution,
    )

    total     = len(specs)
    sequences: List[Tuple[List[AuthEvent], SessionContext]] = []

    for i, spec in enumerate(specs):
        device     = random.choice(devices)
        gateway_id = gateway_ids[i % len(gateway_ids)]

        engine = EventEngine(
            device_id      = device.device_id,
            gateway_id     = gateway_id,
            auth_server_id = auth_server_id,
            broker_id      = broker_id,
            source_ip      = device.ip_address,
            battery_level  = device.battery_level,
        )
        pair = engine.execute(spec)
        sequences.append(pair)

        if progress_callback:
            label = "normal" if not spec.is_anomaly else spec.anomaly_type
            progress_callback(i + 1, total, f"Session {i + 1}/{total} [{label}]")

    return sequences
