"""Event generator for creating ML dataset events."""

import random
from datetime import datetime, timedelta
from typing import Optional

from ..models.device import Device
from ..models.token import Token
from ..models.session import Session
from ..models.event import Event
from .state_machine import LifecycleState


class EventGenerator:
    """
    Generates Event objects representing authentication/activity events.
    
    Configures events based on device, token, session, and lifecycle state
    to create realistic synthetic data for ML model training.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize event generator.
        
        Args:
            seed: Random seed for reproducible generation
        """
        if seed is not None:
            random.seed(seed)
    
    def generate_event(
        self,
        device: Device,
        lifecycle_phase: LifecycleState,
        token: Optional[Token] = None,
        session: Optional[Session] = None,
        is_anomaly: bool = False,
        attack_type: str = "",
        attacker_type: str = "",
    ) -> Event:
        """
        Generate an event for the given device and state.
        
        Args:
            device: Device that triggered the event
            lifecycle_phase: Current lifecycle phase
            token: Token used (if applicable)
            session: Session (if applicable)
            is_anomaly: Whether this is an anomalous event
            attack_type: Type of attack ("" for normal, "replay", etc.)
            attacker_type: Type of attacker ("" for normal, "non-invasive", etc.)
            
        Returns:
            Generated Event object
        """
        event = Event()
        
        # Device identity
        event.device_id = device.device_id
        event.device_type = device.device_type
        event.resource_class = device.resource_class
        event.identity_method = device.identity_method
        event.known_to_registry = device.known_to_registry
        
        # Lifecycle
        event.lifecycle_phase = lifecycle_phase.value
        
        # Authentication
        if lifecycle_phase in [
            LifecycleState.DISCOVERED,
            LifecycleState.PAIRED,
            LifecycleState.ENROLLED,
            LifecycleState.AUTHORIZED,
        ]:
            event.auth_method = device.identity_method
            event.auth_result = "success" if not is_anomaly else "fail"
            event.auth_duration_ms = random.uniform(50, 200)
        
        # Token information
        if token:
            event.token_id = token.token_id
            event.token_valid = token.is_valid()
            event.token_expired = token.is_expired()
            event.token_scope = token.scope
        
        # MQTT specific
        if lifecycle_phase in [
            LifecycleState.MQTT_CONNECTED,
            LifecycleState.ACTIVE,
        ]:
            event.mqtt_version = session.mqtt_version if session else random.choice([3, 4, 5])
            event.qos_level = random.choice([0, 1, 2])
            event.topic = f"sensors/device_{device.device_id}/data"
            event.requested_topic = event.topic
            event.acl_match = True if not is_anomaly else random.choice([True, False])
            
            # Message metrics (normal or anomalous)
            if is_anomaly and attack_type == "replay":
                event.message_frequency = random.uniform(10, 50)  # Higher frequency
                event.latency_ms = random.uniform(500, 2000)  # Higher latency
                event.message_frequency_anomaly_flag = True
                event.latency_anomaly_flag = True
                event.duplicate_message_flag = True
            else:
                event.message_frequency = random.uniform(0.1, 2.0)
                event.latency_ms = random.uniform(10, 100)
            
            event.payload_size_bytes = random.randint(50, 1000)
        
        # Session information
        if session:
            event.mqtt_version = session.mqtt_version
            event.clean_session_flag = session.clean_session
            event.keep_alive_s = session.keep_alive_s
            event.mqtt_conack_val = 0 if event.auth_result == "success" else random.randint(1, 5)
            if session.is_active():
                event.connection_duration_s = (datetime.utcnow() - session.started_at).total_seconds()
        
        # TLS
        event.tls_enabled = True
        
        # Anomaly markers
        event.is_anomaly = is_anomaly
        event.attack_type = attack_type
        event.attacker_type = attacker_type
        
        if is_anomaly and attack_type == "replay":
            event.duplicate_message_flag = True
            event.message_frequency_anomaly_flag = True
        
        return event
    
    def generate_normal_authentication_flow(self, device: Device) -> list[Event]:
        """
        Generate a series of events for a normal authentication flow.
        
        Args:
            device: Device to simulate
            
        Returns:
            List of events representing normal lifecycle progression
        """
        events = []
        
        # Simulate token
        token = Token(device_id=device.device_id, scope="sensors/*")
        token.expires_at = datetime.utcnow() + timedelta(hours=1)
        
        # Simulate session
        session = Session(device_id=device.device_id, token_id=token.token_id)
        
        # Discovery phase
        event = self.generate_event(
            device, LifecycleState.DISCOVERED, token=token
        )
        events.append(event)
        
        # Pairing phase
        event = self.generate_event(
            device, LifecycleState.PAIRED, token=token
        )
        events.append(event)
        
        # Enrollment phase
        event = self.generate_event(
            device, LifecycleState.ENROLLED, token=token
        )
        events.append(event)
        
        # Authorization phase
        event = self.generate_event(
            device, LifecycleState.AUTHORIZED, token=token
        )
        events.append(event)
        
        # MQTT Connection phase
        event = self.generate_event(
            device, LifecycleState.MQTT_CONNECTED, token=token, session=session
        )
        events.append(event)
        
        # Active phase with multiple messages
        for _ in range(3):
            event = self.generate_event(
                device, LifecycleState.ACTIVE, token=token, session=session
            )
            events.append(event)
        
        return events
