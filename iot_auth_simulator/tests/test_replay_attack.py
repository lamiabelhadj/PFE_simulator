"""Unit tests for replay attack scenario."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.models.device import Device
from src.core.flow_engine import FlowEngine
from src.components.auth_server import AuthServer
from src.components.mqtt_broker import MQTTBroker
from src.scenarios.replay_attack import run_replay_attack


def test_replay_attack_basic():
    """Test basic replay attack scenario."""
    device = Device(
        device_id="test_device_replay",
        device_type="sensor",
        resource_class="constrained",
        identity_method="certificate",
        known_to_registry=True,
    )
    
    flow_engine = FlowEngine()
    auth_server = AuthServer("test_server")
    mqtt_broker = MQTTBroker("test_broker")
    
    # Run replay attack
    events = run_replay_attack(device, flow_engine, auth_server, mqtt_broker)
    
    # Assertions
    assert len(events) > 0, "Should generate events"
    assert all(event.device_id == device.device_id for event in events), "All events should be for test device"
    
    print(f"✓ test_replay_attack_basic passed ({len(events)} events generated)")


def test_replay_attack_has_anomalies():
    """Test that replay attack generates anomalies."""
    device = Device(
        device_id="test_device_replay_anomaly",
        device_type="sensor",
        resource_class="constrained",
        identity_method="certificate",
        known_to_registry=True,
    )
    
    flow_engine = FlowEngine()
    auth_server = AuthServer("test_server")
    mqtt_broker = MQTTBroker("test_broker")
    
    events = run_replay_attack(device, flow_engine, auth_server, mqtt_broker)
    
    # Should have anomaly events
    anomaly_events = [e for e in events if e.is_anomaly]
    assert len(anomaly_events) > 0, "Replay attack should generate anomaly events"
    
    # Check for replay attack marker
    replay_events = [e for e in events if e.attack_type == "replay"]
    assert len(replay_events) > 0, "Should have events marked as replay attack"
    
    # Check attacker type
    attacker_events = [e for e in events if e.attacker_type == "non-invasive"]
    assert len(attacker_events) > 0, "Should have events marked as non-invasive attacker"
    
    print(f"✓ test_replay_attack_has_anomalies passed ({len(anomaly_events)} anomaly events)")


def test_replay_attack_phases():
    """Test replay attack generates expected phases."""
    device = Device(
        device_id="test_device_phases",
        device_type="actuator",
        resource_class="moderate",
        identity_method="preshared_key",
        known_to_registry=True,
    )
    
    flow_engine = FlowEngine()
    auth_server = AuthServer("test_server")
    mqtt_broker = MQTTBroker("test_broker")
    
    events = run_replay_attack(device, flow_engine, auth_server, mqtt_broker)
    
    # Should have both normal and replay phases
    phases = set(event.lifecycle_phase for event in events)
    
    # Normal phase should be present
    assert "DISCOVERED" in phases, "Should have discovery phase"
    
    # Replay attack should be detected
    replay_events = [e for e in events if e.attack_type == "replay"]
    assert len(replay_events) > 0, "Should have replay attack events"
    
    print(f"✓ test_replay_attack_phases passed (phases: {sorted(phases)})")


if __name__ == "__main__":
    print("Running replay attack tests...\n")
    try:
        test_replay_attack_basic()
        test_replay_attack_has_anomalies()
        test_replay_attack_phases()
        print("\n✓ All replay attack tests passed!")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
