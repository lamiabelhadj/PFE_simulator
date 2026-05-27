"""
simulator/flows/step4_authorization.py
───────────────────────────────────────
Step 4 — Authorization

The device requests an OAuth2/ACE access token from the AuthServer.
This token will be presented to the MQTT broker in Step 5.
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
    *,
    short_lifetime:    bool = False,
    use_stolen_token:  bool = False,
    stolen_token:      Optional[str] = None,
) -> tuple[dict, Optional[AccessToken]]:
    """
    Execute the Authorization step.

    Parameters
    ----------
    short_lifetime   : request a token with reduced lifetime (attacker pattern)
    use_stolen_token : replay attack — skip issuance, inject a pre-captured token
    stolen_token     : the captured token string used in replay attacks

    Returns
    -------
    (feature_dict, AccessToken | None)
      The token object is passed to Step 5; None on failure.
    """
    device.transition(DeviceState.AUTHORIZING)

    # ── Replay attack shortcut ────────────────────────────────────────────────
    if use_stolen_token and stolen_token:
        return _build_result(
            device=device,
            gateway=gateway,
            token=None,
            token_str=stolen_token,
            success=1,             # attacker believes the token is valid
            reason="token_replayed",
            latency_ms=random.gauss(cfg.network.latency_attack_mean_ms,
                                    cfg.network.latency_attack_std_ms),
            short_lifetime=short_lifetime,
        ), None                    # no real AccessToken object

    # ── Normal token request ──────────────────────────────────────────────────
    t_start  = time.time()
    psk_hash = device.get_psk_hash()

    token, reason = auth_server.issue_token(
        device.device_id,
        psk_hash,
        short_lifetime=short_lifetime,
    )

    latency_ms = max(1.0, (time.time() - t_start) * 1000 + random.gauss(
        cfg.network.latency_normal_mean_ms,
        cfg.network.latency_normal_std_ms,
    ))

    success = 1 if token else 0

    if token:
        # Let the gateway cache the issued token
        gateway.relay_token(device.device_id, token.to_string(), token.issued_at)

    return _build_result(
        device=device,
        gateway=gateway,
        token=token,
        token_str=token.to_string() if token else "",
        success=success,
        reason=reason,
        latency_ms=latency_ms,
        short_lifetime=short_lifetime,
    ), token


def _build_result(
    device:         Device,
    gateway:        Gateway,
    token:          Optional[AccessToken],
    token_str:      str,
    success:        int,
    reason:         str,
    latency_ms:     float,
    short_lifetime: bool,
) -> dict:
    """Assemble the authorization feature dict."""
    token_lifetime = (
        token.lifetime_s if token
        else (cfg.security.token_lifetime_short_s if short_lifetime
              else cfg.security.token_lifetime_s)
    )

    return {
        # Authorization features are stored in the session-level event;
        # the token itself feeds into MQTT session features (step 5).
        "auth_result":     success,
        "auth_reason":     reason,
        "token_lifetime_s": round(token_lifetime, 1),

        # Step metadata
        "step":            "authorization",
        "step_latency_ms": round(latency_ms, 2),
        "step_success":    success,
    }