"""Session model for IoT authentication simulator."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Session:
    """
    Represents an MQTT session for a device.
    
    Attributes:
        session_id: Unique identifier for this session
        device_id: Device this session belongs to
        token_id: Token used for this session
        mqtt_version: MQTT protocol version (3, 4, or 5)
        clean_session: Whether to discard previous session state
        keep_alive_s: Keep-alive interval in seconds
        started_at: When session started
        ended_at: When session ended (if applicable)
        connection_duration_s: Total session duration in seconds
    """
    
    session_id: str = ""
    device_id: str = ""
    token_id: str = ""
    mqtt_version: int = 4
    clean_session: bool = True
    keep_alive_s: int = 60
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    connection_duration_s: float = 0.0
    
    def end_session(self) -> None:
        """End the session and calculate connection duration."""
        self.ended_at = datetime.utcnow()
        delta = self.ended_at - self.started_at
        self.connection_duration_s = delta.total_seconds()
    
    def is_active(self) -> bool:
        """Check if session is still active."""
        return self.ended_at is None
    
    def __str__(self) -> str:
        status = "active" if self.is_active() else "ended"
        return f"Session({self.session_id}, device={self.device_id}, {status})"
