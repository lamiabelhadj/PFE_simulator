"""State machine for device authentication lifecycle."""

from enum import Enum
from typing import Optional, Callable
from datetime import datetime


class LifecycleState(Enum):
    """
    Authentication lifecycle states for IoT devices.
    
    Flow progression:
    INIT -> DISCOVERED -> PAIRED -> ENROLLED -> AUTHORIZED -> 
    MQTT_CONNECTED -> ACTIVE -> [REAUTH_REQUIRED] -> TERMINATED
    
    Can transition to FAILED at any point.
    """
    
    INIT = "INIT"
    DISCOVERED = "DISCOVERED"
    PAIRED = "PAIRED"
    ENROLLED = "ENROLLED"
    AUTHORIZED = "AUTHORIZED"
    MQTT_CONNECTED = "MQTT_CONNECTED"
    ACTIVE = "ACTIVE"
    REAUTH_REQUIRED = "REAUTH_REQUIRED"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class StateMachine:
    """
    Simple state machine for device authentication lifecycle.
    
    Tracks current state and allows transitions between valid states.
    Supports state change callbacks for event generation.
    """
    
    def __init__(self, initial_state: LifecycleState = LifecycleState.INIT):
        """
        Initialize state machine.
        
        Args:
            initial_state: Starting lifecycle state
        """
        self.current_state: LifecycleState = initial_state
        self.state_entered_at: datetime = datetime.utcnow()
        self._callbacks: dict[LifecycleState, list[Callable]] = {}
    
    def register_callback(self, state: LifecycleState, callback: Callable) -> None:
        """
        Register a callback to be called when entering a state.
        
        Args:
            state: Lifecycle state to monitor
            callback: Function to call (receives state as argument)
        """
        if state not in self._callbacks:
            self._callbacks[state] = []
        self._callbacks[state].append(callback)
    
    def transition_to(self, new_state: LifecycleState) -> bool:
        """
        Transition to a new state.
        
        Args:
            new_state: Target lifecycle state
            
        Returns:
            True if transition was successful, False if invalid
        """
        if self._is_valid_transition(self.current_state, new_state):
            self.current_state = new_state
            self.state_entered_at = datetime.utcnow()
            
            # Call registered callbacks
            if new_state in self._callbacks:
                for callback in self._callbacks[new_state]:
                    callback(new_state)
            
            return True
        return False
    
    def _is_valid_transition(
        self, from_state: LifecycleState, to_state: LifecycleState
    ) -> bool:
        """
        Check if a state transition is valid.
        
        Args:
            from_state: Current state
            to_state: Desired target state
            
        Returns:
            True if transition is allowed
        """
        valid_transitions = {
            LifecycleState.INIT: [
                LifecycleState.DISCOVERED,
                LifecycleState.FAILED,
            ],
            LifecycleState.DISCOVERED: [
                LifecycleState.PAIRED,
                LifecycleState.FAILED,
            ],
            LifecycleState.PAIRED: [
                LifecycleState.ENROLLED,
                LifecycleState.FAILED,
            ],
            LifecycleState.ENROLLED: [
                LifecycleState.AUTHORIZED,
                LifecycleState.FAILED,
            ],
            LifecycleState.AUTHORIZED: [
                LifecycleState.MQTT_CONNECTED,
                LifecycleState.FAILED,
            ],
            LifecycleState.MQTT_CONNECTED: [
                LifecycleState.ACTIVE,
                LifecycleState.FAILED,
            ],
            LifecycleState.ACTIVE: [
                LifecycleState.REAUTH_REQUIRED,
                LifecycleState.TERMINATED,
                LifecycleState.FAILED,
            ],
            LifecycleState.REAUTH_REQUIRED: [
                LifecycleState.AUTHORIZED,
                LifecycleState.FAILED,
            ],
            LifecycleState.TERMINATED: [LifecycleState.INIT],
            LifecycleState.FAILED: [LifecycleState.INIT],
        }
        
        return to_state in valid_transitions.get(from_state, [])
    
    def get_time_in_state(self) -> float:
        """Get seconds since entering current state."""
        return (datetime.utcnow() - self.state_entered_at).total_seconds()
    
    def __str__(self) -> str:
        return f"StateMachine(state={self.current_state.value}, time_in_state={self.get_time_in_state():.2f}s)"
