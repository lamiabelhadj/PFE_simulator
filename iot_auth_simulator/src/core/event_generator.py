"""Event generator for creating ML dataset events."""

import hashlib
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
        
        # Identity and discovery
        event.device_id = device.device_id
        event.claimed_device_id = device.device_id
        event.source_ip = self._source_ip_for_device(device.device_id)
        event.registered_device = device.known_to_registry
        event.source_connection_count = random.randint(1, 3)
        event.source_diversity = random.randint(1, 2)

        # Lifecycle
        event.lifecycle_phase = lifecycle_phase.value
        event.event_id = self._event_id(device.device_id)
        event.session_id = session.session_id if session else ""
        event.attack_type = attack_type or "normal"
        event.attack_phase = lifecycle_phase.value if is_anomaly else ""

        # Network baseline
        event.tcp_rtt = random.uniform(15, 120)
        event.packet_rate = random.uniform(0.5, 3.0)
        event.inter_arrival_time = random.uniform(0.2, 2.0)
        event.frame_length = random.randint(64, 512)
        event.tcp_segment_length = max(0, event.frame_length - 54)
        event.connection_duration = random.uniform(0.2, 4.0)

        if lifecycle_phase == LifecycleState.DISCOVERED:
            event.mqtt_msg_type = "DISCOVERY"
            event.event_type = "discovery"
            if is_anomaly:
                event.packet_rate = random.uniform(20, 80)
                event.source_connection_count = random.randint(10, 60)
                event.source_diversity = random.randint(4, 20)

        if lifecycle_phase == LifecycleState.PAIRED:
            event.pairing_result = "success" if not is_anomaly else "fail"
            event.pairing_latency_ms = random.uniform(40, 250)
            if is_anomaly:
                event.pairing_latency_ms = random.uniform(800, 3000)
                event.connection_duration = random.uniform(10, 60)
            event.event_type = "pairing"

        if lifecycle_phase == LifecycleState.FAILED:
            event.auth_result = "fail"
            event.credential_status = "invalid" if not device.known_to_registry else event.credential_status
            event.gateway_decision = "reject"
            event.severity = "medium" if is_anomaly else "low"

        if lifecycle_phase in [LifecycleState.ENROLLED, LifecycleState.AUTHORIZED]:
            event.credential_status = "valid" if not is_anomaly else random.choice(
                ["invalid", "expired", "stolen", "malformed"]
            )
            event.auth_result = "success" if not is_anomaly else "fail"
            event.auth_latency_ms = random.uniform(50, 200)
            event.failed_auth_count = 0 if not is_anomaly else random.randint(1, 8)
            event.username_present = device.identity_method == "username_password"
            event.password_present = device.identity_method == "username_password"
            event.username_length = random.randint(8, 16) if event.username_present else 0
            event.password_length = random.randint(12, 24) if event.password_present else 0
            event.connack_code = 0 if event.auth_result == "success" else random.randint(1, 5)
            event.event_type = "authentication"
        
        # MQTT specific
        if lifecycle_phase in [
            LifecycleState.AUTHORIZED,
            LifecycleState.MQTT_CONNECTED,
            LifecycleState.ACTIVE,
            LifecycleState.REAUTH_REQUIRED,
        ]:
            event.mqtt_version = session.mqtt_version if session else random.choice([3, 4, 5])
            event.mqtt_msg_type = "CONNECT" if lifecycle_phase == LifecycleState.MQTT_CONNECTED else "PUBLISH"
            event.connect_flags = "clean_session" if (not session or session.clean_session) else "session_present"
            event.clean_session = session.clean_session if session else True
            event.keep_alive = session.keep_alive_s if session else 60
            event.qos_level = random.choice([0, 1, 2])
            event.requested_qos = event.qos_level
            event.granted_qos = event.qos_level if not is_anomaly else random.choice([0, 1])
            event.operation = "publish"
            event.requested_topic = f"sensors/device_{device.device_id}/data"
            event.topic_length = len(event.requested_topic)
            event.authorization_result = "allowed" if not is_anomaly else random.choice(["allowed", "denied"])
            event.topic_scope_violation = is_anomaly and random.choice([True, False])
            event.retain_flag = False if not is_anomaly else random.choice([False, True])
            
            # Message metrics (normal or anomalous)
            if is_anomaly and attack_type == "replay":
                event.message_rate = random.uniform(10, 50)
                event.byte_rate = random.uniform(5000, 50000)
                event.duplicate_flag = True
                event.replay_window_violation = True
                event.behavior_deviation_score = random.uniform(0.75, 1.0)
                event.trust_score = random.uniform(0.0, 0.35)
                event.gateway_decision = random.choice(["reject", "block", "re-authenticate"])
                event.severity = "high"
                event.source_ip_change = True
            else:
                event.message_rate = random.uniform(0.1, 2.0)
                event.byte_rate = random.uniform(100, 2000)
                event.behavior_deviation_score = random.uniform(0.0, 0.2)
            
            event.payload_length = random.randint(50, 1000)
            event.hash_method = "BLAKE2s"
            event.payload_hash = self._payload_hash(device.device_id, event.lifecycle_phase, event.payload_length)
            event.message_id = self._message_id(device.device_id)
            if lifecycle_phase == LifecycleState.ACTIVE:
                event.event_type = "publish"
        
        # Session information
        if session:
            event.mqtt_version = session.mqtt_version
            event.clean_session = session.clean_session
            event.keep_alive = session.keep_alive_s
            event.connack_code = 0 if event.auth_result == "success" else random.randint(1, 5)
            event.session_present = True
            if session.is_active():
                event.session_duration = (datetime.utcnow() - session.started_at).total_seconds()
        
        # Anomaly markers
        event.is_anomaly = is_anomaly
        event.attack_type = attack_type or "normal"
        
        if is_anomaly and attack_type == "replay":
            event.duplicate_flag = True
            event.replay_window_violation = True
            event.attack_phase = lifecycle_phase.value
            event.severity = "high"
        
        return event

    @staticmethod
    def _source_ip_for_device(device_id: str) -> str:
        """Create a stable private source IP for a synthetic device."""
        digest = hashlib.blake2s(device_id.encode("utf-8"), digest_size=2).digest()
        return f"10.0.{digest[0]}.{max(2, digest[1])}"

    @staticmethod
    def _payload_hash(device_id: str, phase: str, payload_length: int) -> str:
        seed = f"{device_id}:{phase}:{payload_length}:{random.random()}".encode("utf-8")
        return hashlib.blake2s(seed, digest_size=16).hexdigest()

    @staticmethod
    def _message_id(device_id: str) -> str:
        return f"msg_{device_id}_{random.randint(100000, 999999)}"
    
    def _event_id(self, device_id: str) -> str:
        return f"evt_{device_id}_{random.randint(100000, 999999)}"

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
