"""
simulator/attacks/replay.py
────────────────────────────
Replay Attack

A previously captured valid token is re-used after it has already
been consumed or after the replay window has expired, in an attempt
to gain unauthorised access to the MQTT broker.

Attack flow:
  Steps 1–3 run normally (attacker has a real or stolen identity).
  Step 4 is skipped — the attacker injects a captured token string.
  Step 5 uses that token to try to open an MQTT session.
  Step 6 flags the replay_window_violation.
"""

import random

from config.settings import cfg
from simulator.core.device import Device
from simulator.core.gateway import Gateway
from simulator.core.auth_server import AuthServer, MQTTBroker
from simulator.flows import (
    step1_discovery,
    step2_pairing,
    step3_enrollment,
    step4_authorization,
    step5_mqtt_session,
    step6_reauth,
)


def run(
    attacker:         Device,
    gateway:          Gateway,
    auth_server:      AuthServer,
    broker:           MQTTBroker,
    stolen_token_str: str,
) -> dict:
    """
    Execute a full replay-attack session.

    Parameters
    ----------
    attacker          : Device flagged as is_attacker=True
    stolen_token_str  : a token string captured from a previous legitimate session

    Returns
    -------
    dict — merged feature event with labels.
    """
    event = {}

    # Steps 1-2: normal discovery & pairing
    event.update(step1_discovery.run(attacker, gateway))
    event.update(step2_pairing.run(attacker, gateway))

    # Step 3: enrollment with valid credentials
    event.update(step3_enrollment.run(attacker, gateway, auth_server))

    # Step 4: skip issuance — inject the stolen token
    token_age_s = random.uniform(
        cfg.attack.replay_token_age_min_s,
        cfg.attack.replay_token_age_max_s,
    )
    e4, _ = step4_authorization.run(
        attacker, gateway, auth_server,
        use_stolen_token=True,
        stolen_token=stolen_token_str,
    )
    event.update(e4)
    event["token_age_s"] = round(token_age_s, 1)

    # Step 5: attempt MQTT session with the replayed token
    event.update(step5_mqtt_session.run(
        attacker, gateway, auth_server, broker,
        token=None,
        token_str_override=stolen_token_str,
    ))

    # Step 6: flag replay window violation
    replay_violation = token_age_s > cfg.security.replay_window_s
    event.update(step6_reauth.run(
        attacker, gateway, auth_server,
        token=None,
        token_str_override=stolen_token_str,
        replay_window_violate=replay_violation,
    ))

    # Labels
    event.update({
        "is_anomaly":   1,
        "attack_type":  "replay",
        "attack_phase": _identify_phase(event),
        "severity":     cfg.attack.severity_map["replay"],
    })

    return event


def capture_token(
    device:      Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
) -> str:
    """
    Run a legitimate session and return the token string so the
    replay attacker can reuse it. Called by the runner before
    instantiating the attack session.
    """
    step1_discovery.run(device, gateway)
    step2_pairing.run(device, gateway)
    step3_enrollment.run(device, gateway, auth_server)
    _, token = step4_authorization.run(device, gateway, auth_server)
    return token.to_string() if token else ""


def _identify_phase(event: dict) -> str:
    if event.get("replay_window_violation"):
        return "reauth"
    if event.get("step_success") == 0:
        return "mqtt_session"
    return "authorization"