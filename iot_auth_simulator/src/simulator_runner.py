"""Reusable simulation runner for CLI and web UI entry points."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .components.auth_server import AuthServer
from .components.gateway import Gateway
from .components.mqtt_broker import MQTTBroker
from .core.event_generator import EventGenerator
from .core.flow_engine import FlowEngine
from .exporters.csv_exporter import CSVExporter
from .exporters.json_exporter import JSONExporter
from .models.device import Device
from .models.event import Event
from .scenarios.normal_flow import run_normal_flow
from .scenarios.replay_attack import run_replay_attack


@dataclass(frozen=True)
class SimulationOptions:
    """Options that can be controlled by the UI or CLI."""

    num_devices: int = 5
    include_normal: bool = True
    include_replay: bool = True
    seed: int = 42
    export_dir: Path | None = None


@dataclass(frozen=True)
class SimulationResult:
    """Simulation events and derived metadata."""

    devices: list[Device]
    normal_events: list[Event]
    replay_events: list[Event]
    all_events: list[Event]
    export_dir: Path
    exported_files: dict[str, Path]

    @property
    def anomaly_count(self) -> int:
        return sum(1 for event in self.all_events if event.is_anomaly)


def generate_test_devices(num_devices: int = 5) -> list[Device]:
    """Generate a deterministic set of test devices."""
    device_types = ["sensor", "actuator", "gateway", "controller"]
    resource_classes = ["constrained", "moderate", "high_capability"]
    identity_methods = ["preshared_key", "username_password"]

    return [
        Device(
            device_id=f"device_{i:03d}",
            device_type=device_types[i % len(device_types)],
            resource_class=resource_classes[i % len(resource_classes)],
            identity_method=identity_methods[i % len(identity_methods)],
            known_to_registry=True,
        )
        for i in range(max(1, num_devices))
    ]


def run_simulation(options: SimulationOptions | None = None) -> SimulationResult:
    """Run selected simulator scenarios and export generated datasets."""
    options = options or SimulationOptions()
    base_dir = Path(__file__).resolve().parents[1]
    export_dir = options.export_dir or base_dir / "data" / "generated"

    auth_server = AuthServer("auth_server_1")
    gateway = Gateway("gateway_1")
    mqtt_broker = MQTTBroker("mqtt_broker_1")
    _ = gateway

    devices = generate_test_devices(options.num_devices)
    normal_events: list[Event] = []
    replay_events: list[Event] = []

    for index, device in enumerate(devices):
        if options.include_normal:
            engine = FlowEngine(event_generator=EventGenerator(seed=options.seed + index))
            normal_events.extend(run_normal_flow(device, engine, auth_server, mqtt_broker))

        if options.include_replay:
            engine = FlowEngine(event_generator=EventGenerator(seed=options.seed + 100 + index))
            replay_events.extend(run_replay_attack(device, engine, auth_server, mqtt_broker))

    all_events = [*normal_events, *replay_events]
    exported_files = export_events(
        normal_events=normal_events,
        replay_events=replay_events,
        all_events=all_events,
        output_dir=export_dir,
    )

    return SimulationResult(
        devices=devices,
        normal_events=normal_events,
        replay_events=replay_events,
        all_events=all_events,
        export_dir=export_dir,
        exported_files=exported_files,
    )


def export_events(
    normal_events: Iterable[Event],
    replay_events: Iterable[Event],
    all_events: Iterable[Event],
    output_dir: Path,
) -> dict[str, Path]:
    """Export event collections to CSV and JSON files."""
    output_dir.mkdir(parents=True, exist_ok=True)

    normal_events = list(normal_events)
    replay_events = list(replay_events)
    all_events = list(all_events)

    files = {
        "normal_csv": output_dir / "normal_events.csv",
        "normal_json": output_dir / "normal_events.json",
        "replay_csv": output_dir / "replay_events.csv",
        "replay_json": output_dir / "replay_events.json",
        "all_csv": output_dir / "all_events.csv",
        "all_json": output_dir / "all_events.json",
    }

    CSVExporter.export(normal_events, files["normal_csv"])
    JSONExporter.export(normal_events, files["normal_json"])
    CSVExporter.export(replay_events, files["replay_csv"])
    JSONExporter.export(replay_events, files["replay_json"])
    CSVExporter.export(all_events, files["all_csv"])
    JSONExporter.export(all_events, files["all_json"])

    return files
