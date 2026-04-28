"""MQTT Broker component for IoT authentication simulator.

The MQTT broker performs:
- CONNECT request handling
- Token/session validation
- PUBLISH event reception
- Message topic routing
"""

import logging
from typing import Optional, List
from ..models.token import Token
from ..models.session import Session

logger = logging.getLogger(__name__)


class MQTTBroker:
    """
    MQTT Broker component for IoT authentication.
    
    Accepts CONNECT requests, validates tokens/sessions,
    and receives PUBLISH events.
    """
    
    def __init__(self, broker_id: str, host: str = "mqtt.cloud.example.com"):
        """
        Initialize MQTT broker.
        
        Args:
            broker_id: Unique identifier for this broker
            host: Broker hostname
        """
        self.broker_id = broker_id
        self.host = host
        self.connected_clients: dict[str, Session] = {}
        self.published_messages: List[dict] = []
    
    def handle_connect(
        self,
        device_id: str,
        token: Token,
        mqtt_version: int = 4,
        clean_session: bool = True,
        keep_alive_s: int = 60,
    ) -> tuple[bool, int, Optional[Session]]:
        """
        Handle MQTT CONNECT request.
        
        Args:
            device_id: Device requesting connection
            token: Authentication token
            mqtt_version: MQTT protocol version (3, 4, or 5)
            clean_session: Whether to start fresh session
            keep_alive_s: Keep-alive interval in seconds
            
        Returns:
            Tuple of (success: bool, conack_value: int, session: Optional[Session])
            conack_value: 0=accepted, 1-5=various failures
        """
        # Validate token
        if token is None or token.is_expired():
            logger.warning(f"MQTT Broker {self.broker_id}: Connection rejected for {device_id} - invalid token")
            return False, 4, None  # conack=4: not authorized
        
        # Create session
        session = Session(
            session_id=f"session_{device_id}_{len(self.connected_clients)}",
            device_id=device_id,
            token_id=token.token_id,
            mqtt_version=mqtt_version,
            clean_session=clean_session,
            keep_alive_s=keep_alive_s,
        )
        
        self.connected_clients[session.session_id] = session
        token.mark_used()
        
        logger.info(f"MQTT Broker {self.broker_id}: Client {device_id} connected (MQTT v{mqtt_version})")
        return True, 0, session  # conack=0: connection accepted
    
    def handle_disconnect(self, session_id: str) -> bool:
        """
        Handle MQTT DISCONNECT request.
        
        Args:
            session_id: Session to disconnect
            
        Returns:
            True if disconnect successful
        """
        if session_id not in self.connected_clients:
            return False
        
        session = self.connected_clients[session_id]
        session.end_session()
        del self.connected_clients[session_id]
        
        logger.info(f"MQTT Broker {self.broker_id}: Client {session.device_id} disconnected")
        return True
    
    def handle_publish(
        self,
        session_id: str,
        topic: str,
        payload: bytes,
        qos: int = 0,
    ) -> bool:
        """
        Handle MQTT PUBLISH request.
        
        Args:
            session_id: Session publishing message
            topic: MQTT topic
            payload: Message payload
            qos: Quality of Service level (0, 1, or 2)
            
        Returns:
            True if publish successful
        """
        if session_id not in self.connected_clients:
            logger.warning(f"MQTT Broker {self.broker_id}: Publish on unknown session {session_id}")
            return False
        
        session = self.connected_clients[session_id]
        
        # Record message
        message = {
            "session_id": session_id,
            "device_id": session.device_id,
            "topic": topic,
            "payload_size": len(payload),
            "qos": qos,
        }
        self.published_messages.append(message)
        
        logger.debug(f"MQTT Broker {self.broker_id}: Received PUBLISH from {session.device_id} on {topic}")
        return True
    
    def is_client_connected(self, session_id: str) -> bool:
        """Check if a client session is connected."""
        return session_id in self.connected_clients
    
    def __str__(self) -> str:
        return f"MQTTBroker({self.broker_id}, connected={len(self.connected_clients)}, messages={len(self.published_messages)})"
