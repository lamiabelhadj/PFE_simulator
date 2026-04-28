"""Main entry point for IoT authentication flow simulator.

This script runs the complete simulator with multiple scenarios:
- Normal authentication flow
- Replay attack scenario

Generates synthetic labeled data for ML-based anomaly detection.
"""

import logging
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.models.device import Device
from src.core.flow_engine import FlowEngine
from src.core.event_generator import EventGenerator
from src.components.auth_server import AuthServer
from src.components.gateway import Gateway
from src.components.mqtt_broker import MQTTBroker
from src.scenarios.normal_flow import run_normal_flow
from src.scenarios.replay_attack import run_replay_attack
from src.exporters.csv_exporter import CSVExporter
from src.exporters.json_exporter import JSONExporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def generate_test_devices() -> list[Device]:
    """Generate a set of test devices."""
    devices = []
    device_types = ["sensor", "actuator", "gateway", "controller"]
    resource_classes = ["constrained", "moderate", "high_capability"]
    identity_methods = ["certificate", "preshared_key", "username_password"]
    
    for i in range(5):
        device = Device(
            device_id=f"device_{i:03d}",
            device_type=device_types[i % len(device_types)],
            resource_class=resource_classes[i % len(resource_classes)],
            identity_method=identity_methods[i % len(identity_methods)],
            known_to_registry=True,  # All devices known for this test
        )
        devices.append(device)
    
    return devices


def main():
    """Run the IoT authentication simulator."""
    logger.info("=" * 80)
    logger.info("IoT Authentication Flow Simulator")
    logger.info("=" * 80)
    
    # Initialize components
    flow_engine = FlowEngine(event_generator=EventGenerator(seed=42))
    auth_server = AuthServer("auth_server_1")
    gateway = Gateway("gateway_1")
    mqtt_broker = MQTTBroker("mqtt_broker_1")
    
    logger.info(f"Initialized: {auth_server}")
    logger.info(f"Initialized: {gateway}")
    logger.info(f"Initialized: {mqtt_broker}")
    
    # Generate test devices
    devices = generate_test_devices()
    logger.info(f"Generated {len(devices)} test devices")
    
    # Collections for all events
    all_normal_events = []
    all_replay_events = []
    all_events = []
    
    # Run scenarios for each device
    for device in devices:
        logger.info("")
        logger.info(f"Processing device: {device}")
        
        # Reset flow engine for each device
        flow_engine = FlowEngine(event_generator=EventGenerator())
        
        # Scenario 1: Normal flow
        logger.info("-" * 40)
        logger.info(f"Scenario 1: Normal flow for {device.device_id}")
        logger.info("-" * 40)
        try:
            normal_events = run_normal_flow(device, flow_engine, auth_server, mqtt_broker)
            all_normal_events.extend(normal_events)
            all_events.extend(normal_events)
            logger.info(f"✓ Normal flow generated {len(normal_events)} events")
        except Exception as e:
            logger.error(f"✗ Error in normal flow: {e}", exc_info=True)
        
        # Reset for replay attack
        flow_engine = FlowEngine(event_generator=EventGenerator())
        
        # Scenario 2: Replay attack
        logger.info("-" * 40)
        logger.info(f"Scenario 2: Replay attack for {device.device_id}")
        logger.info("-" * 40)
        try:
            replay_events = run_replay_attack(device, flow_engine, auth_server, mqtt_broker)
            all_replay_events.extend(replay_events)
            all_events.extend(replay_events)
            logger.info(f"✓ Replay attack generated {len(replay_events)} events")
        except Exception as e:
            logger.error(f"✗ Error in replay attack: {e}", exc_info=True)
        
        logger.info("")
    
    # Export data
    logger.info("=" * 80)
    logger.info("Exporting events to CSV and JSON")
    logger.info("=" * 80)
    
    output_dir = Path(__file__).parent / "data" / "generated"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Export normal events
    csv_path = output_dir / "normal_events.csv"
    json_path = output_dir / "normal_events.json"
    CSVExporter.export(all_normal_events, csv_path)
    JSONExporter.export(all_normal_events, json_path)
    
    # Export replay attack events
    csv_path = output_dir / "replay_events.csv"
    json_path = output_dir / "replay_events.json"
    CSVExporter.export(all_replay_events, csv_path)
    JSONExporter.export(all_replay_events, json_path)
    
    # Export all events
    csv_path = output_dir / "all_events.csv"
    json_path = output_dir / "all_events.json"
    CSVExporter.export(all_events, csv_path)
    JSONExporter.export(all_events, json_path)
    
    # Summary
    logger.info("")
    logger.info("=" * 80)
    logger.info("Simulation Summary")
    logger.info("=" * 80)
    logger.info(f"Total devices simulated: {len(devices)}")
    logger.info(f"Normal flow events: {len(all_normal_events)}")
    logger.info(f"Replay attack events: {len(all_replay_events)}")
    logger.info(f"Total events: {len(all_events)}")
    logger.info(f"Normal events anomaly count: {sum(1 for e in all_normal_events if e.is_anomaly)}")
    logger.info(f"Replay events anomaly count: {sum(1 for e in all_replay_events if e.is_anomaly)}")
    logger.info(f"Total anomaly count: {sum(1 for e in all_events if e.is_anomaly)}")
    logger.info("")
    logger.info(f"Exported to: {output_dir}")
    logger.info("=" * 80)
    logger.info("✓ Simulator completed successfully")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
