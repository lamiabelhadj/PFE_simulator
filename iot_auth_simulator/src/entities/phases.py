"""Concrete Phase entities for the six authentication lifecycle phases."""

from .base import Phase
from ..core.state_machine import LifecycleState


class DiscoveredPhase(Phase):
    def __init__(self):
        super().__init__(LifecycleState.DISCOVERED)


class PairedPhase(Phase):
    def __init__(self):
        super().__init__(LifecycleState.PAIRED)


class EnrolledPhase(Phase):
    def __init__(self):
        super().__init__(LifecycleState.ENROLLED)


class AuthorizedPhase(Phase):
    def __init__(self):
        super().__init__(LifecycleState.AUTHORIZED)


class MQTTConnectedPhase(Phase):
    def __init__(self):
        super().__init__(LifecycleState.MQTT_CONNECTED)


class ActivePhase(Phase):
    def __init__(self):
        super().__init__(LifecycleState.ACTIVE)


# Registry factory
def default_phase_registry() -> dict:
    """Return a mapping from LifecycleState to Phase instance."""
    return {
        LifecycleState.DISCOVERED: DiscoveredPhase(),
        LifecycleState.PAIRED: PairedPhase(),
        LifecycleState.ENROLLED: EnrolledPhase(),
        LifecycleState.AUTHORIZED: AuthorizedPhase(),
        LifecycleState.MQTT_CONNECTED: MQTTConnectedPhase(),
        LifecycleState.ACTIVE: ActivePhase(),
    }
