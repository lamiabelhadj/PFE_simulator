"""
simulator/flows/step5_mqtt_session.py
──────────────────────────────────────
Step 5 — MQTT Session

The device establishes a secure MQTT session. The broker validates
the token before allowing Publish/Subscribe operations.
"""

import hashlib
import random
import time
from typing import Optional

from config.settings import cfg
from simulator.core.device import Device, DeviceState
from simulator.core.gateway import Gateway
from simulator.core.auth_server import AuthServer, AccessToken, MQTTBroker


def run(
    device:      Device,
    gateway:     Gateway,
    auth_server: AuthServer,
    broker:      MQTTBroker,
    token:       Optional[AccessToken],
    *,
    token_str_override: Optional[str] = None,
    flood_mode:         bool          = False,
    num_flood_msgs:     int           = 500,
) -> dict:
    """
    Execute the MQTT Session step.

    Parameters
    ----------
    token              : valid AccessToken from Step 4 (None if attack bypassed it)
    token_str_override : inject a different token string (replay / impersonation)
    flood_mode         : DoS — send a burst of messages instead of a normal session
    num_flood_msgs     : number of messages in flood burst

    Returns
    -------
    dict — feature slice for this step.
    """
    device.transition(DeviceState.SESSION_OPEN)

    token_str = token_str_override or (token.to_string() if token else "")

    # ── MQTT CONNECT ──────────────────────────────────────────────────────────
    keep_alive = (
        cfg.device.keep_alive_short_s if flood_mode
        else cfg.device.keep_alive_normal_s
    )

    connect_ok, connack_code, session_meta = broker.connect(
        device_id     = device.device_id,
        token_string  = token_str,
        auth_server   = auth_server,
        clean_session = True,
        keep_alive_s  = keep_alive,
    )

    if not connect_ok:
        return _build_result(
            device=device,
            connect_ok=False,
            connack_code=connack_code,
            session_meta=session_meta,
            pub_result="n/a",
            sub_result="n/a",
            granted_qos=0,
            message_rate=0.0,
            byte_rate=0.0,
            session_duration=0.0,
            flood_mode=flood_mode,
            num_messages=0,
            total_bytes=0,
        )

    # ── Determine session parameters ──────────────────────────────────────────
    qos_level = random.choice(cfg.mqtt.qos_levels)
    topic     = f"{cfg.mqtt.topic_prefix}/{device.device_id[:8]}/telemetry"

    if flood_mode:
        return _run_flood(device, broker, topic, qos_level, num_flood_msgs, connack_code, session_meta)
    else:
        return _run_normal(device, broker, topic, qos_level, connack_code, session_meta)


# ── Normal session ─────────────────────────────────────────────────────────────

def _run_normal(
    device:       Device,
    broker:       MQTTBroker,
    topic:        str,
    qos_level:    int,
    connack_code: str,
    session_meta: dict,
) -> dict:
    num_messages = random.randint(3, 20)
    total_bytes  = 0
    pub_result   = "n/a"
    sub_result   = "n/a"
    granted_qos  = 0

    # Subscribe first
    sub_ok, granted_qos, _ = broker.subscribe(device.device_id, topic, qos=qos_level)
    sub_result = "granted" if sub_ok else "rejected"

    # Publish messages
    for _ in range(num_messages):
        payload_size = random.randint(cfg.mqtt.payload_size_min, cfg.mqtt.payload_size_max)
        payload      = bytes(random.getrandbits(8) for _ in range(payload_size))
        pub_ok, reason = broker.publish(device.device_id, topic, payload, qos=qos_level)
        pub_result   = reason
        total_bytes += payload_size

    session_duration = random.uniform(
        cfg.mqtt.session_duration_min_s,
        cfg.mqtt.session_duration_max_s,
    )
    message_rate = num_messages / max(session_duration, 1)
    byte_rate    = total_bytes  / max(session_duration, 1)

    broker.disconnect(device.device_id)

    return _build_result(
        device=device,
        connect_ok=True,
        connack_code=connack_code,
        session_meta=session_meta,
        pub_result=pub_result,
        sub_result=sub_result,
        granted_qos=granted_qos,
        message_rate=round(message_rate, 3),
        byte_rate=round(byte_rate, 2),
        session_duration=round(session_duration, 2),
        flood_mode=False,
        num_messages=num_messages,
        total_bytes=total_bytes,
    )


# ── DoS / Flood session ────────────────────────────────────────────────────────

def _run_flood(
    device:       Device,
    broker:       MQTTBroker,
    topic:        str,
    qos_level:    int,
    num_messages: int,
    connack_code: str,
    session_meta: dict,
) -> dict:
    total_bytes = 0

    for _ in range(num_messages):
        payload_size = random.randint(
            cfg.mqtt.payload_size_max,
            cfg.mqtt.payload_size_dos_max,
        )
        payload      = bytes(random.getrandbits(8) for _ in range(min(payload_size, 512)))
        broker.publish(device.device_id, topic, payload, qos=qos_level)
        total_bytes += payload_size

    session_duration = cfg.attack.dos_duration_s
    message_rate     = num_messages / max(session_duration, 1)
    byte_rate        = total_bytes  / max(session_duration, 1)

    broker.disconnect(device.device_id)

    return _build_result(
        device=device,
        connect_ok=True,
        connack_code=connack_code,
        session_meta=session_meta,
        pub_result="published",
        sub_result="n/a",
        granted_qos=qos_level,
        message_rate=round(message_rate, 3),
        byte_rate=round(byte_rate, 2),
        session_duration=round(session_duration, 2),
        flood_mode=True,
        num_messages=num_messages,
        total_bytes=total_bytes,
    )


# ── Feature assembler ──────────────────────────────────────────────────────────

def _build_result(
    device:           Device,
    connect_ok:       bool,
    connack_code:     str,
    session_meta:     dict,
    pub_result:       str,
    sub_result:       str,
    granted_qos:      int,
    message_rate:     float,
    byte_rate:        float,
    session_duration: float,
    flood_mode:       bool,
    num_messages:     int,
    total_bytes:      int,
) -> dict:

    message_id     = random.randint(1, 65535)
    duplicate_flag = 0
    payload_sample = bytes(random.randint(0, 255) for _ in range(16))
    payload_hash   = hashlib.blake2s(payload_sample).hexdigest()

    return {
        # MQTT Session features 
        "message_id":        message_id,
        "duplicate_flag":    duplicate_flag,
        "payload_length":    total_bytes,
        "payload_hash":      payload_hash,
        "qos_level":         granted_qos,
        "message_rate":      message_rate,
        "byte_rate":         byte_rate,
        "session_duration":  session_duration,

        # Authorization features
        "requested_topic":       f"{cfg.mqtt.topic_prefix}/{device.device_id[:8]}/telemetry",
        "topic_length":          len(f"{cfg.mqtt.topic_prefix}/{device.device_id[:8]}/telemetry"),
        "operation":             "pub_sub",
        "requested_qos":         granted_qos,
        "granted_qos":           granted_qos,
        "authorization_result":  int(connect_ok),
        "topic_scope_violation": int(pub_result == "topic_scope_violation"),
        "retain_flag":           0,

        # Session context
        "connack_code":    connack_code,
        "session_present": int(session_meta.get("session_present", False)),
        "mqtt_version":    cfg.mqtt.mqtt_version,

        # Step metadata
        "step":            "mqtt_session",
        "step_latency_ms": round(random.gauss(cfg.network.latency_normal_mean_ms,
                                              cfg.network.latency_normal_std_ms), 2),
        "step_success":    int(connect_ok),
    }