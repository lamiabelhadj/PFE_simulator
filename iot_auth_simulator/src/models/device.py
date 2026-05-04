"""Device model for IoT authentication simulator."""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Device:
    """
    Represents an IoT device with authentication attributes.
    
    Attributes:
        device_id: Unique identifier for the device
        device_type: Type of device (sensor, actuator, gateway, controller)
        resource_class: Resource capability (constrained, moderate, high_capability)
        identity_method: Method of identity verification (preshared_key, username_password)
        known_to_registry: Whether device is registered in the auth server registry
        mac_address: MAC address of the device
        firmware_version: Device firmware version
        created_at: Timestamp when device was created
    """
    
    device_id: str
    device_type: str
    resource_class: str
    identity_method: str
    known_to_registry: bool = True
    mac_address: str = ""
    firmware_version: str = "1.0.0"
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def __str__(self) -> str:
        return f"Device({self.device_id}, type={self.device_type}, class={self.resource_class})"
