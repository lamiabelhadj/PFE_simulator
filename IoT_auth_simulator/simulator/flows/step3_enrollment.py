"""
simulator/flows/step3_enrollment.py
────────────────────────────────────
Step 3 — Enrollment

The device sends its identity (PSK hash) to be verified and
registered by the AuthServer. The gateway gates the request
before forwarding it.
"""

import random
import time

from config.settings import cfg
from simulator.core.device import Device, DeviceState
from simulator.core.gateway import Gateway
from simulator.core.auth_server import AuthServer


def run(
    device:      Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    *,
    credential_valid: bool = True,
    claimed_device_id: str = None,
) -> dict:
    """
    Execute the Enrollment step.

    Parameters
    ----------
    credential_valid  : set False to simulate an attacker with a bad PSK
    claimed_device_id : override claimed identity (used by impersonation attack)

    Returns
    -------
    dict — feature slice for this step.
    """
    device.transition(DeviceState.ENROLLING)

    claimed_id = claimed_device_id or device.device_id

    # ── Gateway access control ────────────────────────────────────────────────
    allowed, gw_reason = gateway.allow_enrollment(claimed_id, device.ip_address)

    if not allowed:
        device.register_failed_auth()
        gateway.record_session_failure(claimed_id)
        return _build_result(
            device, gateway, claimed_id,
            auth_result=0,
            connack_code=gw_reason,
            latency_ms=random.gauss(5.0, 1.0),
            credential_valid=credential_valid,
        )

    # ── AuthServer enrollment ─────────────────────────────────────────────────
    t_start  = time.time()
    psk_hash = device.get_psk_hash()

    success, connack_code = auth_server.enroll_device(
        claimed_id,
        psk_hash,
        credential_valid=credential_valid,
    )

    latency_ms = max(1.0, (time.time() - t_start) * 1000 + random.gauss(
        cfg.network.latency_normal_mean_ms,
        cfg.network.latency_normal_std_ms,
    ))

    if success:
        device.register_successful_auth()
        gateway.record_session_success(claimed_id)
    else:
        device.register_failed_auth()
        gateway.record_session_failure(claimed_id)

    return _build_result(
        device, gateway, claimed_id,
        auth_result=int(success),
        connack_code=connack_code,
        latency_ms=latency_ms,
        credential_valid=credential_valid,
    )


def _build_result(
    device:           Device,
    gateway:          Gateway,
    claimed_id:       str,
    auth_result:      int,
    connack_code:     str,
    latency_ms:       float,
    credential_valid: bool,
) -> dict:
    """Assemble the enrollment feature dict."""
    username_present = 1
    password_length  = cfg.device.psk_length_bytes * 2   # hex-encoded PSK hash length

    return {
        # Enrollment & Authentication features 
        "claimed_device_id":  claimed_id,
        "credential_status":  int(credential_valid),
        "mqtt_msg_type":      "CONNECT",
        "connect_flags":      0xC2,          # username + password flags set
        "clean_session":      1,
        "username_present":   username_present,
        "password_length":    password_length,
        "keep_alive":         cfg.device.keep_alive_normal_s,
        "mqtt_version":       cfg.mqtt.mqtt_version,
        "connack_code":       connack_code,
        "auth_result":        auth_result,
        "auth_latency_ms":    round(latency_ms, 2),
        "failed_auth_count":  device.failed_auth_count,

        # Step metadata
        "step":            "enrollment",
        "step_latency_ms": round(latency_ms, 2),
        "step_success":    auth_result,
    }