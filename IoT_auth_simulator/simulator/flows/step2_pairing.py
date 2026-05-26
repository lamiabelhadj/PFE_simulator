"""
simulator/flows/step2_pairing.py
─────────────────────────────────
Step 2 — Pairing

The device and gateway establish a secure channel via an ECDH key
exchange before any authentication credentials are transmitted.
"""

import random
import time

from config.settings import cfg
from simulator.core.device import Device, DeviceState
from simulator.core.gateway import Gateway


def run(device: Device, gateway: Gateway) -> dict:
    """
    Execute the Pairing step (ECDH handshake).

    Returns
    -------
    dict — feature slice for this step.
    """
    device.transition(DeviceState.PAIRING)

    # ── ECDH exchange ─────────────────────────────────────────────────────────
    t_start = time.time()

    device_pub_key          = device.generate_ecdh_keypair()
    gw_pub_key, _           = gateway.perform_ecdh_exchange(device.device_id, device_pub_key)
    device.compute_shared_secret(gw_pub_key)

    pairing_latency_ms = max(1.0, (time.time() - t_start) * 1000 + random.gauss(
        cfg.network.latency_normal_mean_ms,
        cfg.network.latency_normal_std_ms,
    ))

    pairing_result = 1   # success

    # ── TCP / network features ────────────────────────────────────────────────
    connection_duration_ms = round(pairing_latency_ms * random.uniform(1.8, 3.5), 2)
    tcp_flags              = "SYN,ACK"
    tcp_segment_len        = random.randint(128, 512)

    return {
        # Pairing & Network features (slide 14)
        "tcp_flags":           tcp_flags,
        "connection_duration": connection_duration_ms,
        "tcp_segment_len":     tcp_segment_len,
        "pairing_result":      pairing_result,
        "pairing_latency_ms":  round(pairing_latency_ms, 2),

        # Step metadata
        "step":            "pairing",
        "step_latency_ms": round(pairing_latency_ms, 2),
        "step_success":    pairing_result,
    }