"""Replay attack scenario."""

import logging
from typing import List

from ..models.device import Device
from ..models.event import Event
from ..core.state_machine import LifecycleState
from ..core.flow_engine import FlowEngine
from ..components.auth_server import AuthServer
from ..components.mqtt_broker import MQTTBroker
from .normal_flow import run_normal_flow

logger = logging.getLogger(__name__)


def run_replay_attack(
    device: Device,
    flow_engine: FlowEngine,
    auth_server: AuthServer,
    mqtt_broker: MQTTBroker,
) -> List[Event]:
    """
    Simulate a replay attack scenario.
    
    Flow:
    1. Run a normal authentication flow to get a valid token
    2. Capture the token_id from the legitimate session
    3. End the legitimate session
    4. Attacker attempts to reuse the captured token_id in a new CONNECT
    5. If token is expired or already used, connection fails (auth_result = "fail")
    6. Mark events as anomalous with attack_type="replay"
    
    Args:
        device: Device to simulate
        flow_engine: Flow orchestration engine
        auth_server: Authentication server component
        mqtt_broker: MQTT broker component
        
    Returns:
        List of events including both legitimate and replay attack events
    """
    events = []
    
    logger.info(f"Starting replay attack scenario for {device.device_id}")
    
    # 1. Run legitimate authentication flow first
    logger.info("Phase 1: Legitimate authentication")
    legitimate_events = run_normal_flow(device, flow_engine, auth_server, mqtt_broker)
    events.extend(legitimate_events)
    
    # Extract the captured token from events
    captured_token_id = None
    captured_session_id = None
    for event in legitimate_events:
        if event.token_id and event.lifecycle_phase in ["AUTHORIZED", "MQTT_CONNECTED", "ACTIVE"]:
            captured_token_id = event.token_id
            captured_session_id = event.token_id  # We'll use token_id as reference
            break
    
    if not captured_token_id:
        logger.error("Failed to capture token for replay attack")
        return events
    
    logger.info(f"Captured token: {captured_token_id[:8]}...")
    
    # 2. Clean up the legitimate session
    for session_id, session in list(flow_engine.active_sessions.items()):
        if session.device_id == device.device_id:
            mqtt_broker.handle_disconnect(session_id)
            del flow_engine.active_sessions[session_id]
    
    # Reset device to INIT state for next attempt
    flow_engine.state_machines[device.device_id].current_state = LifecycleState.INIT
    
    logger.info("Legitimate session terminated")
    logger.info("Phase 2: Replay attack attempt")
    
    # 3. Attacker attempts to reuse captured token
    # Get the captured token object
    captured_token = flow_engine.active_tokens.get(captured_token_id)
    
    if captured_token is None:
        # Token was already removed, simulate expired token
        logger.info(f"Token {captured_token_id[:8]}... not found (simulating expired token)")
        
        # Generate a failed auth event
        flow_engine.transition_device(device.device_id, LifecycleState.DISCOVERED)
        event = flow_engine.generate_event(
            device.device_id,
            is_anomaly=True,
            attack_type="replay",
            attacker_type="non-invasive",
        )
        event.auth_result = "fail"
        event.token_expired = True
        event.lifecycle_phase = LifecycleState.AUTHORIZED.value
        events.append(event)
        logger.warning(f"Replay attack failed (expired token): {event}")
    else:
        # Token exists but check if it's expired or already used
        flow_engine.transition_device(device.device_id, LifecycleState.DISCOVERED)
        
        if captured_token.is_expired():
            event = flow_engine.generate_event(
                device.device_id,
                is_anomaly=True,
                attack_type="replay",
                attacker_type="non-invasive",
            )
            event.auth_result = "fail"
            event.token_expired = True
            event.lifecycle_phase = LifecycleState.AUTHORIZED.value
            events.append(event)
            logger.warning(f"Replay attack failed (token expired): {event}")
        elif captured_token.used:
            # Token was already used
            event = flow_engine.generate_event(
                device.device_id,
                is_anomaly=True,
                attack_type="replay",
                attacker_type="non-invasive",
            )
            event.auth_result = "fail"
            event.duplicate_message_flag = True
            event.lifecycle_phase = LifecycleState.AUTHORIZED.value
            events.append(event)
            logger.warning(f"Replay attack detected (token reuse): {event}")
        else:
            # Token still valid - attacker succeeds (but we mark as anomaly based on duplicate flag)
            flow_engine.transition_device(device.device_id, LifecycleState.AUTHORIZED)
            
            success, conack, session = mqtt_broker.handle_connect(
                device.device_id,
                captured_token,
                mqtt_version=4,
                clean_session=False,  # Reusing session
                keep_alive_s=60,
            )
            
            if success:
                flow_engine.active_sessions[session.session_id] = session
                flow_engine.transition_device(device.device_id, LifecycleState.MQTT_CONNECTED)
                
                # Generate anomalous events
                event = flow_engine.generate_event(
                    device.device_id,
                    is_anomaly=True,
                    attack_type="replay",
                    attacker_type="non-invasive",
                )
                event.duplicate_message_flag = True
                event.message_frequency_anomaly_flag = True
                event.lifecycle_phase = LifecycleState.MQTT_CONNECTED.value
                events.append(event)
                logger.warning(f"Replay attack succeeded (anomalous connection): {event}")
                
                # Generate more anomalous messages
                flow_engine.transition_device(device.device_id, LifecycleState.ACTIVE)
                for i in range(2):
                    mqtt_broker.handle_publish(
                        session.session_id,
                        f"sensors/device_{device.device_id}/data",
                        payload=b"replayed_data",
                        qos=1,
                    )
                    event = flow_engine.generate_event(
                        device.device_id,
                        is_anomaly=True,
                        attack_type="replay",
                        attacker_type="non-invasive",
                    )
                    event.duplicate_message_flag = True
                    event.lifecycle_phase = LifecycleState.ACTIVE.value
                    events.append(event)
                    logger.warning(f"Replay attack active event {i+1}: {event}")
                
                # Cleanup
                mqtt_broker.handle_disconnect(session.session_id)
    
    logger.info(f"Replay attack scenario complete. Generated {len(events)} events")
    return events
