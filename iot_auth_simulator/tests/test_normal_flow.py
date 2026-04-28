"""Unit tests for normal authentication flow."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.models.device import Device
from src.core.flow_engine import FlowEngine
from src.components.auth_server import AuthServer
from src.components.mqtt_broker import MQTTBroker
from src.scenarios.normal_flow import run_normal_flow


def test_normal_flow_basic():
    """Test basic normal flow scenario."""
    # Create test device
    device = Device(
        device_id="test_device_001",
        device_type="sensor",
        resource_class="constrained",
        identity_method="certificate",
        known_to_registry=True,
    )
    
    # Initialize components
    flow_engine = FlowEngine()
    auth_server = AuthServer("test_server")
    mqtt_broker = MQTTBroker("test_broker")
    
    # Run normal flow
    events = run_normal_flow(device, flow_engine, auth_server, mqtt_broker)
    
    # Assertions
    assert len(events) > 0, "Should generate events"
    assert all(event.device_id == device.device_id for event in events), "All events should be for test device"
    
    # Check for expected phases
    phases = [event.lifecycle_phase for event in events]
    expected_phases = ["DISCOVERED", "PAIRED", "ENROLLED", "AUTHORIZED"]
    for phase in expected_phases:
        assert phase in phases, f"Should have {phase} phase"
    
    # Check that normal events don't have anomaly flag
    normal_anomalies = [e for e in events if e.is_anomaly]
    assert len(normal_anomalies) == 0, "Normal flow should not have anomalies"
    
    print(f"✓ test_normal_flow_basic passed ({len(events)} events generated)")


def test_normal_flow_known_device():
    """Test normal flow with known device."""
    device = Device(
        device_id="known_device",
        device_type="actuator",
        resource_class="moderate",
        identity_method="preshared_key",
        known_to_registry=True,
    )
    
    flow_engine = FlowEngine()
    auth_server = AuthServer("test_server")
    mqtt_broker = MQTTBroker("test_broker")
    
    events = run_normal_flow(device, flow_engine, auth_server, mqtt_broker)
    
    # Should reach MQTT connection phase
    phases = [event.lifecycle_phase for event in events]
    assert "MQTT_CONNECTED" in phases, "Known device should reach MQTT_CONNECTED phase"
    assert "ACTIVE" in phases, "Known device should have ACTIVE phase"
    
    print(f"✓ test_normal_flow_known_device passed ({len(events)} events generated)")


def test_normal_flow_unknown_device():
    """Test normal flow with unknown device (should fail)."""
    device = Device(
        device_id="unknown_device",
        device_type="sensor",
        resource_class="constrained",
        identity_method="certificate",
        known_to_registry=False,
    )
    
    flow_engine = FlowEngine()
    auth_server = AuthServer("test_server")
    mqtt_broker = MQTTBroker("test_broker")
    
    events = run_normal_flow(device, flow_engine, auth_server, mqtt_broker)
    
    # Should fail at enrollment
    phases = [event.lifecycle_phase for event in events]
    assert "FAILED" in phases, "Unknown device should fail enrollment"
    assert "MQTT_CONNECTED" not in phases, "Unknown device should not reach MQTT phase"
    
    print(f"✓ test_normal_flow_unknown_device passed ({len(events)} events generated)")


if __name__ == "__main__":
    print("Running normal flow tests...\n")
    try:
        test_normal_flow_basic()
        test_normal_flow_known_device()
        test_normal_flow_unknown_device()
        print("\n✓ All normal flow tests passed!")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
