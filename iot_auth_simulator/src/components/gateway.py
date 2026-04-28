"""Gateway component for IoT authentication simulator.

The gateway performs:
- Discovery and pairing with devices
- ACL enforcement
- Rate limiting
- Traffic aggregation
"""

import logging
from typing import Optional
from ..models.device import Device

logger = logging.getLogger(__name__)


class Gateway:
    """
    Edge/Gateway component for IoT authentication.
    
    Performs device discovery, pairing, ACL enforcement,
    rate limiting, and traffic aggregation.
    """
    
    def __init__(self, gateway_id: str):
        """
        Initialize gateway.
        
        Args:
            gateway_id: Unique identifier for this gateway
        """
        self.gateway_id = gateway_id
        self.discovered_devices: dict[str, Device] = {}
        self.paired_devices: dict[str, Device] = {}
        self.active_connections: dict[str, dict] = {}
    
    def discover_device(self, device: Device) -> bool:
        """
        Discover a device (simulated mDNS/CoAP discovery).
        
        Args:
            device: Device to discover
            
        Returns:
            True if discovery successful
        """
        self.discovered_devices[device.device_id] = device
        logger.info(f"Gateway {self.gateway_id}: Discovered device {device.device_id}")
        return True
    
    def pair_device(self, device_id: str) -> bool:
        """
        Pair with a discovered device.
        
        Args:
            device_id: ID of device to pair with
            
        Returns:
            True if pairing successful
        """
        if device_id not in self.discovered_devices:
            return False
        
        device = self.discovered_devices[device_id]
        self.paired_devices[device_id] = device
        logger.info(f"Gateway {self.gateway_id}: Paired with device {device_id}")
        return True
    
    def check_acl(self, device_id: str, topic: str, operation: str = "publish") -> bool:
        """
        Check Access Control List for device operation.
        
        Args:
            device_id: Device requesting access
            topic: MQTT topic
            operation: "publish" or "subscribe"
            
        Returns:
            True if ACL allows operation
        """
        if device_id not in self.paired_devices:
            return False
        
        # Simplified ACL: devices can access their own topics
        allowed_pattern = f"sensors/device_{device_id}/*"
        matches = topic.startswith(f"sensors/device_{device_id}")
        
        logger.debug(f"Gateway {self.gateway_id}: ACL check for {device_id} on {topic}: {matches}")
        return matches
    
    def apply_rate_limit(self, device_id: str, message_count: int, window_s: float = 1.0) -> bool:
        """
        Apply rate limiting to device.
        
        Args:
            device_id: Device ID
            message_count: Number of messages
            window_s: Time window in seconds
            
        Returns:
            True if within rate limit
        """
        # Simplified rate limiting: max 100 msg/sec per device
        max_rate = 100 / window_s
        return message_count <= max_rate
    
    def __str__(self) -> str:
        return f"Gateway({self.gateway_id}, discovered={len(self.discovered_devices)}, paired={len(self.paired_devices)})"
