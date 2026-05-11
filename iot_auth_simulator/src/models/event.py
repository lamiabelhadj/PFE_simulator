"""Event model for IoT authentication simulator - ML dataset generation."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    """
    Represents a single authentication/activity event for ML dataset generation.
    
    Includes all fields needed for anomaly detection model training.
    See README.md for field descriptions.
    """
    
    # Temporal
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Identity and Discovery Features
    device_id: str = ""
    claimed_device_id: str = ""
    source_ip: str = ""
    gateway_id: str = "gateway_1"
    registered_device: bool = True
    source_connection_count: int = 1
    source_diversity: int = 1
    
    # Pairing and Network Features
    tcp_flags: str = "SYN,ACK"
    connection_duration: float = 0.0
    tcp_rtt: float = 0.0
    packet_rate: float = 0.0
    inter_arrival_time: float = 0.0
    frame_length: int = 0
    tcp_segment_len: int = 0
    pairing_result: str = ""
    pairing_latency_ms: float = 0.0
    
    # Enrollment and Authentication Features
    credential_status: str = ""
    mqtt_msg_type: str = ""
    connect_flags: str = ""
    clean_session: bool = True
    username_present: bool = False
    password_present: bool = False
    username_length: int = 0
    password_length: int = 0
    keep_alive: int = 60
    mqtt_version: int = 4
    connack_code: int = 0
    auth_result: str = "success"
    auth_latency_ms: float = 0.0
    failed_auth_count: int = 0
    
    # Authorization Features
    requested_topic: str = ""
    topic_length: int = 0
    operation: str = ""
    requested_qos: int = 0
    granted_qos: int = 0
    authorization_result: str = "allowed"
    topic_scope_violation: bool = False
    retain_flag: bool = False
    
    # MQTT Session Features
    message_id: str = ""
    duplicate_flag: bool = False
    payload_length: int = 0
    payload_hash: str = ""
    qos_level: int = 0
    message_rate: float = 0.0
    byte_rate: float = 0.0
    session_duration: float = 0.0
    
    # Continuous Re-authentication Features
    trust_score: float = 1.0
    re_auth_required: bool = False
    gateway_decision: str = "accept"
    session_present: bool = False
    source_ip_change: bool = False
    replay_window_violation: bool = False
    behavior_deviation_score: float = 0.0
    
    # Labels
    lifecycle_phase: str = ""  # DISCOVERED, PAIRED, ENROLLED, AUTHORIZED, etc.
    is_anomaly: bool = False
    attack_type: str = "normal"
    attack_phase: str = ""
    severity: str = "low"
    attacker_type: str = ""
    
    def to_dict(self) -> dict:
        """Convert event to dictionary for export."""
        event_dict = asdict(self)
        # Convert datetime to ISO format string
        event_dict["timestamp"] = self.timestamp.isoformat()
        return event_dict
    
    def __str__(self) -> str:
        anomaly_marker = "[ANOMALY]" if self.is_anomaly else "[NORMAL]"
        return f"Event {anomaly_marker} {self.timestamp.isoformat()} | Device: {self.device_id} | Phase: {self.lifecycle_phase} | Result: {self.auth_result}"
