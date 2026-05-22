"""
simulator/flows/step1_discovery.py
───────────────────────────────────
Step 1 — Discovery

The IoT device discovers the gateway and available services
in order to initiate the simulated authentication flow.
"""

import random
import time

from config.settings import cfg
from simulator.core.device import Device, DeviceState
from simulator.core.gateway import Gateway


def run(device: Device, gateway: Gateway) -> dict:
    """
    Execute the Discovery step.

    The device probes the network, the gateway responds with a
    service advertisement. Latency and packet-rate are sampled
    from the normal distribution defined in NetworkConfig.

    Returns
    -------
    dict — feature slice for this step (merged into the session event).
    """
    device.transition(DeviceState.DISCOVERING)
    t_start = time.time()

    # ── Simulate network latency ──────────────────────────────────────────────
    latency_ms = max(1.0, random.gauss(
        cfg.network.latency_normal_mean_ms,
        cfg.network.latency_normal_std_ms,
    ))

    # ── Gateway responds ──────────────────────────────────────────────────────
    advertisement = gateway.respond_to_discovery(device.device_id, device.ip_address)

    # ── Network-level features ────────────────────────────────────────────────
    packet_rate = max(0.1, random.gauss(
        cfg.network.packet_rate_normal_mean,
        cfg.network.packet_rate_normal_std,
    ))
    inter_arrival_time = round(1000.0 / packet_rate, 2)   # ms between packets
    frame_length       = random.randint(64, 256)           # bytes — typical discovery probe
    tcp_rtt_ms         = max(1.0, random.gauss(
        cfg.network.rtt_normal_mean_ms,
        cfg.network.rtt_normal_std_ms,
    ))

    # Update device connection counter
    device.source_connection_count += 1

    # Retrieve session from gateway for diversity tracking
    session = gateway.get_session(device.device_id)

    return {
        # Identity & Discovery features 
        "device_id":               device.device_id,
        "claimed_device_id":       device.device_id,      # same at discovery; diverges in attacks
        "source_ip":               device.ip_address,
        "gateway_id":              gateway.gateway_id,
        "registered_device":       int(device.credential_valid),
        "source_connection_count": device.source_connection_count,
        "source_diversity":        session.source_diversity if session else 1,
        "battery_level":           device.battery_level,

        # Network features 
        "tcp_rtt":             round(tcp_rtt_ms, 2),
        "packet_rate":         round(packet_rate, 3),
        "inter_arrival_time":  inter_arrival_time,
        "frame_length":        frame_length,

        # Step metadata
        "step":                "discovery",
        "step_latency_ms":     round(latency_ms, 2),
        "step_success":        1,
    }