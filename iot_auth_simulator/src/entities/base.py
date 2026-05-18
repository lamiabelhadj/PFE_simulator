"""Base Phase entity for the authentication flow."""

from typing import Optional

from ..models.device import Device
from ..models.token import Token
from ..models.session import Session
from ..models.event import Event
from ..core.state_machine import LifecycleState


class Phase:
    """Base class for a lifecycle phase entity.

    Subclasses may override `pre_handle`, `post_handle` to execute
    phase-specific logic before/after the default event generation.
    """

    def __init__(self, state: LifecycleState):
        self.state = state

    def pre_handle(
        self,
        engine,
        device: Device,
        token: Optional[Token],
        session: Optional[Session],
        is_anomaly: bool,
        attack_type: str,
        attacker_type: str,
    ) -> None:
        """Hook executed before handling the phase."""
        return None

    def post_handle(self, event: Event) -> Event:
        """Hook executed after the event is generated."""
        return event

    def handle(
        self,
        engine,
        device: Device,
        token: Optional[Token] = None,
        session: Optional[Session] = None,
        is_anomaly: bool = False,
        attack_type: str = "",
        attacker_type: str = "",
    ) -> Event:
        """Default handler: call EventGenerator to build an Event for this phase."""
        self.pre_handle(engine, device, token, session, is_anomaly, attack_type, attacker_type)
        event = engine.event_generator.generate_event(
            device=device,
            lifecycle_phase=self.state,
            token=token,
            session=session,
            is_anomaly=is_anomaly,
            attack_type=attack_type,
            attacker_type=attacker_type,
        )
        event = self.post_handle(event)
        return event
