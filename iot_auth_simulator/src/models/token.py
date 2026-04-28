"""Token model for IoT authentication simulator."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import uuid


@dataclass
class Token:
    """
    Represents an authentication token issued to a device.
    
    Attributes:
        token_id: Unique identifier for this token
        device_id: Device this token was issued to
        issued_at: Timestamp when token was issued
        expires_at: Timestamp when token expires
        scope: Authorization scope (comma-separated topics/resources)
        used: Whether this token has been used for MQTT connection
        used_at: Timestamp when token was first used
    """
    
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str = ""
    issued_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    scope: str = ""  # e.g., "sensors/temperature,sensors/humidity"
    used: bool = False
    used_at: Optional[datetime] = None
    
    def is_valid(self) -> bool:
        """Check if token is still valid (not expired)."""
        if self.expires_at is None:
            return True
        return datetime.utcnow() < self.expires_at
    
    def is_expired(self) -> bool:
        """Check if token has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() >= self.expires_at
    
    def mark_used(self) -> None:
        """Mark token as used."""
        self.used = True
        self.used_at = datetime.utcnow()
    
    def __str__(self) -> str:
        status = "valid" if self.is_valid() else "expired"
        return f"Token({self.token_id[:8]}..., device={self.device_id}, {status})"
