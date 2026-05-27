"""
simulator/flows/step6_reauth.py
────────────────────────────────
Step 6 — Re-authentication

The system performs periodic token revalidation to maintain
continuous Zero-Trust authentication throughout the MQTT session.
"""

import random
import time
from typing import Optional

from config.settings import cfg
from simulator.core.device import Device, DeviceState
from simulator.core.gateway import Gateway
from simulator.core.auth_server import AuthServer, AccessToken


def run(
    device:      Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    token:       Optional[AccessToken],
    *,
    token_str_override:    Optional[str] = None,
    force_ip_change:       bool          = False,
    replay_window_violate: bool          = False,
) -> dict:
    """
    Execute the Re-authentication step.

    Parameters
    ----------
    token                 : current session token
    token_str_override    : inject a different token string (attack scenarios)
    force_ip_change       : simulate the device reconnecting from a new IP
    replay_window_violate : mark that the token was seen outside the replay window

    Returns
    -------
    dict — feature slice for this step.
    """
    device.transition(DeviceState.REAUTHENTCNG)

    token_str = token_str_override or (token.to_string() if token else "")

    # ── Simulate IP change ────────────────────────────────────────────────────
    source_ip_change = 0
    if force_ip_change:
        new_ip = f"{cfg.network.device_subnet}{random.randint(1, 254)}"
        session = gateway.get_session(device.device_id)
        if session:
            session.register_ip(new_ip)
        source_ip_change = 1

    # ── Gateway Zero-Trust decision ───────────────────────────────────────────
    reauth_required, gw_decision = gateway.trigger_reauth(
        device.device_id, device.trust_score
    )

    # ── AuthServer token revalidation ─────────────────────────────────────────
    t_start = time.time()
    valid, reason = auth_server.revalidate_token(token_str)

    latency_ms = max(1.0, (time.time() - t_start) * 1000 + random.gauss(
        cfg.network.latency_normal_mean_ms,
        cfg.network.latency_normal_std_ms,
    ))

    # ── Trust score update ────────────────────────────────────────────────────
    if valid:
        device.register_successful_auth()
        gateway.record_session_success(device.device_id)
    else:
        device.register_failed_auth()
        gateway.record_session_failure(device.device_id)

    # ── Behavior deviation score ──────────────────────────────────────────────
    # A simple heuristic: combines trust degradation, IP change, and replay signals
    behavior_deviation_score = round(
        (1.0 - device.trust_score)
        + (0.3 * source_ip_change)
        + (0.4 * int(replay_window_violate)),
        3,
    )
    behavior_deviation_score = min(behavior_deviation_score, 1.0)

    return {
        # Continuous Re-authentication features 
        "trust_score":              round(device.trust_score, 3),
        "re_auth_required":         int(reauth_required),
        "gateway_decision":         gw_decision,
        "session_present":          int(not reauth_required),
        "source_ip_change":         source_ip_change,
        "replay_window_violation":  int(replay_window_violate),
        "behavior_deviation_score": behavior_deviation_score,

        # Step metadata
        "step":            "reauth",
        "step_latency_ms": round(latency_ms, 2),
        "step_success":    int(valid),
    }