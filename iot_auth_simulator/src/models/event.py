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
    
    # Device Identity
    device_id: str = ""
    device_type: str = ""
    resource_class: str = ""
    identity_method: str = ""
    known_to_registry: bool = True
    
    # Authentication Lifecycle
    lifecycle_phase: str = ""  # DISCOVERED, PAIRED, ENROLLED, AUTHORIZED, etc.
    auth_method: str = ""
    auth_result: str = "success"  # success or fail
    auth_duration_ms: float = 0.0
    tls_enabled: bool = True
    
    # Token Information
    token_id: str = ""
    token_valid: bool = True
    token_expired: bool = False
    token_scope: str = ""
    
    # Authorization & MQTT
    requested_topic: str = ""
    token_scope_match: bool = True
    mqtt_version: int = 4
    qos_level: int = 0
    topic: str = ""
    acl_match: bool = True
    
    # Message/Connection Metrics
    message_frequency: float = 0.0  # messages per second
    payload_size_bytes: int = 0
    latency_ms: float = 0.0
    connection_duration_s: float = 0.0
    keep_alive_s: int = 60
    clean_session_flag: bool = True
    mqtt_conack_val: int = 0  # 0=accepted, 1-5=various connection refusals
    
    # Anomaly Indicators
    duplicate_message_flag: bool = False
    message_frequency_anomaly_flag: bool = False
    latency_anomaly_flag: bool = False
    
    # Attack Information
    attack_type: str = ""  # empty string for normal, "replay", "impersonation", etc.
    attacker_type: str = ""  # "non-invasive", "invasive", etc.
    is_anomaly: bool = False
    
    def to_dict(self) -> dict:
        """Convert event to dictionary for export."""
        event_dict = asdict(self)
        # Convert datetime to ISO format string
        event_dict["timestamp"] = self.timestamp.isoformat()
        return event_dict
    
    def __str__(self) -> str:
        anomaly_marker = "[ANOMALY]" if self.is_anomaly else "[NORMAL]"
        return f"Event {anomaly_marker} {self.timestamp.isoformat()} | Device: {self.device_id} | Phase: {self.lifecycle_phase} | Result: {self.auth_result}"
