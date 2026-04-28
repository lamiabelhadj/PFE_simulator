"""Flow engine for orchestrating authentication scenarios."""

import logging
from typing import Optional, List

from ..models.device import Device
from ..models.token import Token
from ..models.session import Session
from ..models.event import Event
from .state_machine import LifecycleState, StateMachine
from .event_generator import EventGenerator

logger = logging.getLogger(__name__)


class FlowEngine:
    """
    Orchestrates device authentication flows and manages state transitions.
    
    Coordinates between devices, tokens, sessions, and event generation
    to simulate realistic authentication scenarios.
    """
    
    def __init__(self, event_generator: Optional[EventGenerator] = None):
        """
        Initialize flow engine.
        
        Args:
            event_generator: EventGenerator instance (creates one if not provided)
        """
        self.event_generator = event_generator or EventGenerator()
        self.devices: dict[str, Device] = {}
        self.state_machines: dict[str, StateMachine] = {}
        self.active_tokens: dict[str, Token] = {}
        self.active_sessions: dict[str, Session] = {}
    
    def register_device(self, device: Device) -> None:
        """
        Register a device with the engine.
        
        Args:
            device: Device to register
        """
        self.devices[device.device_id] = device
        self.state_machines[device.device_id] = StateMachine()
        logger.info(f"Registered device: {device}")
    
    def issue_token(self, device_id: str, scope: str = "sensors/*") -> Optional[Token]:
        """
        Issue a token to a device.
        
        Args:
            device_id: Device ID
            scope: Token authorization scope
            
        Returns:
            Issued Token or None if device not found
        """
        if device_id not in self.devices:
            return None
        
        token = Token(device_id=device_id, scope=scope)
        self.active_tokens[token.token_id] = token
        logger.info(f"Issued token {token.token_id[:8]}... to {device_id}")
        return token
    
    def create_session(self, device_id: str, token_id: str) -> Optional[Session]:
        """
        Create an MQTT session for a device.
        
        Args:
            device_id: Device ID
            token_id: Token ID to use for session
            
        Returns:
            Created Session or None if device/token not found
        """
        if device_id not in self.devices or token_id not in self.active_tokens:
            return None
        
        session = Session(device_id=device_id, token_id=token_id)
        self.active_sessions[session.session_id] = session
        logger.info(f"Created session {session.session_id} for {device_id}")
        return session
    
    def end_session(self, session_id: str) -> bool:
        """
        End an active MQTT session.
        
        Args:
            session_id: Session ID to end
            
        Returns:
            True if session was ended, False if not found
        """
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        session.end_session()
        logger.info(f"Ended session {session_id} (duration: {session.connection_duration_s:.2f}s)")
        return True
    
    def transition_device(self, device_id: str, new_state: LifecycleState) -> bool:
        """
        Transition a device to a new lifecycle state.
        
        Args:
            device_id: Device ID
            new_state: Target lifecycle state
            
        Returns:
            True if transition succeeded
        """
        if device_id not in self.state_machines:
            return False
        
        success = self.state_machines[device_id].transition_to(new_state)
        if success:
            logger.info(f"Device {device_id} transitioned to {new_state.value}")
        else:
            logger.warning(f"Invalid transition for device {device_id} to {new_state.value}")
        return success
    
    def get_device_state(self, device_id: str) -> Optional[LifecycleState]:
        """Get current lifecycle state of a device."""
        if device_id not in self.state_machines:
            return None
        return self.state_machines[device_id].current_state
    
    def generate_event(
        self,
        device_id: str,
        is_anomaly: bool = False,
        attack_type: str = "",
        attacker_type: str = "",
    ) -> Optional[Event]:
        """
        Generate an event for a device.
        
        Args:
            device_id: Device ID
            is_anomaly: Whether this is an anomalous event
            attack_type: Type of attack
            attacker_type: Type of attacker
            
        Returns:
            Generated Event or None if device not found
        """
        if device_id not in self.devices:
            return None
        
        device = self.devices[device_id]
        lifecycle_phase = self.get_device_state(device_id)
        
        # Get current token and session
        token = None
        session = None
        
        for token_id, t in self.active_tokens.items():
            if t.device_id == device_id and t.is_valid():
                token = t
                break
        
        for session_id, s in self.active_sessions.items():
            if s.device_id == device_id and s.is_active():
                session = s
                break
        
        event = self.event_generator.generate_event(
            device=device,
            lifecycle_phase=lifecycle_phase,
            token=token,
            session=session,
            is_anomaly=is_anomaly,
            attack_type=attack_type,
            attacker_type=attacker_type,
        )
        
        return event
