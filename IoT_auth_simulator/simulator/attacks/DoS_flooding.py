"""
simulator/attacks/dos_flooding.py
───────────────────────────────────
DoS / Flooding Attack

The attacker saturates the broker or gateway with a high volume of
authentication requests and/or MQTT messages, aiming to exhaust
resources and deny service to legitimate devices.

Two flooding strategies are simulated:

  • auth_flood  : rapid repeated CONNECT requests at the enrollment
                  stage, triggering rate-limiting at the gateway
  • mqtt_flood  : legitimate connection followed by a burst of
                  oversized PUBLISH messages (Step 5 flood mode)
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
    attacker:    Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
    strategy:    str = "mqtt_flood",   # "auth_flood" | "mqtt_flood"
) -> dict:
    """
    Execute a full DoS/Flooding attack session.

    Parameters
    ----------
    attacker  : Device flagged as is_attacker=True
    strategy  : flooding strategy to use

    Returns
    -------
    dict — merged feature event with labels.
    """
    if strategy == "auth_flood":
        return _auth_flood(attacker, gateway, auth_server, broker)
    else:
        return _mqtt_flood(attacker, gateway, auth_server, broker)


# ── Auth-flood ─────────────────────────────────────────────────────────────────

def _auth_flood(
    attacker:    Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
) -> dict:
    """
    Rapidly fire enrollment requests to exhaust gateway rate limits.
    The attacker sends cfg.attack.dos_connection_burst requests in quick
    succession, most of which get rate-limited after the first few.
    """
    event = {}

    # Step 1 — discovery (single probe, high connection count)
    attacker.source_connection_count += cfg.attack.dos_connection_burst
    event.update(step1_discovery.run(attacker, gateway))

    # Inflate packet rate to flood levels
    event["packet_rate"]        = round(random.gauss(
        cfg.network.packet_rate_dos_mean,
        cfg.network.packet_rate_dos_std,
    ), 2)
    event["inter_arrival_time"] = round(1000.0 / max(event["packet_rate"], 1), 3)

    # Step 2 — pairing
    event.update(step2_pairing.run(attacker, gateway))

    # Step 3 — flood the gateway with rapid enrollment attempts
    # Most will be rate-limited; record the last result
    last_e3 = {}
    blocked_count = 0
    for i in range(cfg.attack.dos_connection_burst):
        e3 = step3_enrollment.run(attacker, gateway, auth_server)
        last_e3 = e3
        if e3["connack_code"] == "rate_limited":
            blocked_count += 1

    event.update(last_e3)
    event["dos_blocked_count"] = blocked_count

    # Steps 4-6 — minimal (attacker mostly cares about denying service)
    event.update({
        "auth_result":      0,
        "auth_reason":      "dos_auth_flood",
        "token_lifetime_s": 0,
        "step":             "authorization",
        "step_latency_ms":  round(random.gauss(
            cfg.network.latency_attack_mean_ms,
            cfg.network.latency_attack_std_ms,
        ), 2),
        "step_success": 0,
    })
    event.update(_empty_mqtt_features())
    event.update(_empty_reauth_features(attacker))

    event.update({
        "is_anomaly":   1,
        "attack_type":  "dos_flooding",
        "attack_phase": "enrollment",
        "severity":     cfg.attack.severity_map["dos_flooding"],
    })

    return event


# ── MQTT-flood ─────────────────────────────────────────────────────────────────

def _mqtt_flood(
    attacker:    Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
) -> dict:
    """
    Enroll and authenticate normally, then flood the broker with
    oversized PUBLISH messages via Step 5 flood mode.
    """
    event = {}

    event.update(step1_discovery.run(attacker, gateway))
    event.update(step2_pairing.run(attacker, gateway))
    event.update(step3_enrollment.run(attacker, gateway, auth_server))

    e4, token = step4_authorization.run(attacker, gateway, auth_server)
    event.update(e4)

    # Step 5 — flood mode: high volume, oversized payloads
    num_flood_msgs = int(random.gauss(
        cfg.network.packet_rate_dos_mean * cfg.attack.dos_duration_s,
        cfg.network.packet_rate_dos_std,
    ))
    num_flood_msgs = max(50, num_flood_msgs)

    event.update(step5_mqtt_session.run(
        attacker, gateway, auth_server, broker, token,
        flood_mode=True,
        num_flood_msgs=num_flood_msgs,
    ))

    event.update(step6_reauth.run(attacker, gateway, auth_server, token))

    event.update({
        "is_anomaly":   1,
        "attack_type":  "dos_flooding",
        "attack_phase": "mqtt_session",
        "severity":     cfg.attack.severity_map["dos_flooding"],
    })

    return event


# ── Helpers ────────────────────────────────────────────────────────────────────

def _empty_mqtt_features() -> dict:
    """Return zeroed-out MQTT features for sessions that never reached Step 5."""
    return {
        "message_id":             0,
        "duplicate_flag":         0,
        "payload_length":         0,
        "payload_hash":           "",
        "qos_level":              0,
        "message_rate":           0.0,
        "byte_rate":              0.0,
        "session_duration":       0.0,
        "requested_topic":        "",
        "topic_length":           0,
        "operation":              "none",
        "requested_qos":          0,
        "granted_qos":            0,
        "authorization_result":   0,
        "topic_scope_violation":  0,
        "retain_flag":            0,
        "connack_code":           "dos_blocked",
        "session_present":        0,
        "mqtt_version":           cfg.mqtt.mqtt_version,
        "step":                   "mqtt_session",
        "step_latency_ms":        0.0,
        "step_success":           0,
    }


def _empty_reauth_features(device: Device) -> dict:
    """Return zeroed-out re-auth features for sessions that never reached Step 6."""
    return {
        "trust_score":              round(device.trust_score, 3),
        "re_auth_required":         0,
        "gateway_decision":         "dos_blocked",
        "session_present":          0,
        "source_ip_change":         0,
        "replay_window_violation":  0,
        "behavior_deviation_score": round(1.0 - device.trust_score, 3),
        "step":                     "reauth",
        "step_latency_ms":          0.0,
        "step_success":             0,
    }