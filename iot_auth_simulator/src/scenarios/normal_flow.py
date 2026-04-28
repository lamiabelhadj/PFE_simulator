"""Normal authentication flow scenario."""

import logging
from typing import List

from ..models.device import Device
from ..models.event import Event
from ..core.state_machine import LifecycleState
from ..core.flow_engine import FlowEngine
from ..components.auth_server import AuthServer
from ..components.mqtt_broker import MQTTBroker

logger = logging.getLogger(__name__)


def run_normal_flow(
    device: Device,
    flow_engine: FlowEngine,
    auth_server: AuthServer,
    mqtt_broker: MQTTBroker,
) -> List[Event]:
    """
    Simulate normal device authentication and activity flow.
    
    Flow:
    1. Device discovers gateway/broker
    2. Device performs pairing
    3. Device enrolls successfully (if known_to_registry = True)
    4. Auth server issues token
    5. Device connects to MQTT broker using token
    6. Device publishes normal MQTT messages
    7. Session ends
    
    Args:
        device: Device to simulate
        flow_engine: Flow orchestration engine
        auth_server: Authentication server component
        mqtt_broker: MQTT broker component
        
    Returns:
        List of events generated during flow
    """
    events = []
    
    logger.info(f"Starting normal flow for {device.device_id}")
    
    # 1. Discovery phase
    flow_engine.register_device(device)
    flow_engine.transition_device(device.device_id, LifecycleState.DISCOVERED)
    event = flow_engine.generate_event(device.device_id)
    events.append(event)
    logger.info(f"Discovery event: {event}")
    
    # 2. Pairing phase
    flow_engine.transition_device(device.device_id, LifecycleState.PAIRED)
    event = flow_engine.generate_event(device.device_id)
    events.append(event)
    logger.info(f"Pairing event: {event}")
    
    # 3. Enrollment phase
    if device.known_to_registry:
        auth_server.register_device(device)
        flow_engine.transition_device(device.device_id, LifecycleState.ENROLLED)
        event = flow_engine.generate_event(device.device_id)
        events.append(event)
        logger.info(f"Enrollment event: {event}")
    else:
        flow_engine.transition_device(device.device_id, LifecycleState.FAILED)
        event = flow_engine.generate_event(device.device_id)
        events.append(event)
        logger.warning(f"Enrollment failed (unknown device): {event}")
        return events
    
    # 4. Authorization phase - Issue token
    token = auth_server.issue_token(device.device_id, scope="sensors/*")
    flow_engine.active_tokens[token.token_id] = token
    
    flow_engine.transition_device(device.device_id, LifecycleState.AUTHORIZED)
    event = flow_engine.generate_event(device.device_id)
    events.append(event)
    logger.info(f"Authorization event: {event}")
    
    # 5. MQTT Connection phase
    success, conack, session = mqtt_broker.handle_connect(
        device.device_id,
        token,
        mqtt_version=4,
        clean_session=True,
        keep_alive_s=60,
    )
    
    if success:
        flow_engine.active_sessions[session.session_id] = session
        flow_engine.transition_device(device.device_id, LifecycleState.MQTT_CONNECTED)
        event = flow_engine.generate_event(device.device_id)
        events.append(event)
        logger.info(f"MQTT connected event: {event}")
        
        # 6. Active phase - Publish messages
        flow_engine.transition_device(device.device_id, LifecycleState.ACTIVE)
        for i in range(3):
            mqtt_broker.handle_publish(
                session.session_id,
                f"sensors/device_{device.device_id}/data",
                payload=b"temperature=23.5,humidity=45",
                qos=1,
            )
            event = flow_engine.generate_event(device.device_id)
            events.append(event)
            logger.info(f"Active event {i+1}: {event}")
        
        # 7. Disconnect
        mqtt_broker.handle_disconnect(session.session_id)
        flow_engine.transition_device(device.device_id, LifecycleState.TERMINATED)
        event = flow_engine.generate_event(device.device_id)
        events.append(event)
        logger.info(f"Termination event: {event}")
    else:
        flow_engine.transition_device(device.device_id, LifecycleState.FAILED)
        event = flow_engine.generate_event(device.device_id)
        events.append(event)
        logger.warning(f"MQTT connection failed: {event}")
    
    return events
