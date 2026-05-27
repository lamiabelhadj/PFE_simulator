"""
simulator/attacks/impersonation.py
────────────────────────────────────
Impersonation Attack

The attacker claims to be a legitimate registered device by using
a stolen or forged device_id. Two sub-variants are simulated:

  • stolen_identity : attacker reuses a valid device_id + PSK hash
                      (e.g. obtained through eavesdropping)
  • forged_identity : attacker uses the correct device_id but a
                      wrong PSK hash → enrollment fails

Attack flow:
  Step 1 — discovery from attacker IP (may differ from victim IP)
  Step 2 — normal ECDH pairing
  Step 3 — enrollment with claimed_device_id = victim's id
  Step 4 — token request under stolen identity
  Step 5 — MQTT session (succeeds only if PSK matched)
  Step 6 — re-auth with possible IP change flag
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
    victim_device_id: str,
    stolen_psk_hash:  str  = None,
) -> dict:
    """
    Execute a full impersonation-attack session.

    Parameters
    ----------
    attacker          : Device flagged as is_attacker=True
    victim_device_id  : device_id the attacker claims to be
    stolen_psk_hash   : if provided, attacker has the victim's real PSK hash
                        (stolen identity); if None, attacker forges credentials

    Returns
    -------
    dict — merged feature event with labels.
    """
    event = {}

    # Decide whether the attacker connects from a different IP
    ip_changed = random.random() < cfg.attack.impersonation_ip_change_prob

    # Steps 1-2: discovery and pairing from attacker's own IP
    event.update(step1_discovery.run(attacker, gateway))
    event.update(step2_pairing.run(attacker, gateway))

    # Step 3: enroll using the victim's device_id
    # credential_valid=True only when the attacker has the real PSK hash
    credential_valid = stolen_psk_hash is not None

    # Temporarily override the attacker's PSK hash to the stolen one
    original_psk = attacker.psk
    if stolen_psk_hash:
        # Inject stolen hash by monkey-patching get_psk_hash for this call
        attacker._stolen_psk_hash = stolen_psk_hash

    e3 = step3_enrollment.run(
        attacker, gateway, auth_server,
        credential_valid=credential_valid,
        claimed_device_id=victim_device_id,
    )
    event.update(e3)

    # Step 4: request token under the victim's identity
    # Only succeeds if enrollment went through with the right PSK
    if e3["step_success"]:
        # Register victim id with stolen psk in auth_server if not yet there
        if stolen_psk_hash and not auth_server.is_registered(victim_device_id):
            auth_server._registry[victim_device_id] = stolen_psk_hash

        e4, token = step4_authorization.run(attacker, gateway, auth_server)
        event.update(e4)
    else:
        # Enrollment failed — fabricate a failed auth event
        event.update({
            "auth_result":      0,
            "auth_reason":      "enrollment_failed",
            "token_lifetime_s": 0,
            "step":             "authorization",
            "step_latency_ms":  round(random.gauss(8.0, 2.0), 2),
            "step_success":     0,
        })
        token = None

    # Step 5: MQTT session (will fail if no valid token)
    event.update(step5_mqtt_session.run(
        attacker, gateway, auth_server, broker, token,
    ))

    # Step 6: re-auth — IP change is a key signal here
    event.update(step6_reauth.run(
        attacker, gateway, auth_server, token,
        force_ip_change=ip_changed,
    ))

    # Claimed vs actual device_id mismatch is the core impersonation signal
    event["claimed_device_id"] = victim_device_id
    event["source_ip_change"]  = int(ip_changed)

    # Labels
    event.update({
        "is_anomaly":   1,
        "attack_type":  "impersonation",
        "attack_phase": _identify_phase(e3, event),
        "severity":     cfg.attack.severity_map["impersonation"],
    })

    return event


def _identify_phase(e3: dict, event: dict) -> str:
    if e3["step_success"] == 0:
        return "enrollment"
    if event.get("source_ip_change"):
        return "reauth"
    return "mqtt_session"