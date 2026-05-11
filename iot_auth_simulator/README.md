# IoT Authentication Flow Simulator - Module Documentation

This folder contains the core simulation engine for generating synthetic IoT authentication datasets.

For the complete project overview, objectives, architecture, and features, see the **[Global README](../README.md)** in the parent directory.

## 📁 Folder Structure & Components

This section explains what each module contains and its role in the simulator.

### 📄 Root Files

- **`main.py`** — Entry point for the simulator. Runs all scenarios and exports datasets
- **`requirements.txt`** — Python package dependencies (pydantic, PyYAML, python-dateutil)
- **`README.md`** — This file

### ⚙️ config/
Configuration and settings:
- **`settings.yaml`** — Simulator parameters (device types, token expiration, MQTT settings, export paths)

### 🧠 src/

Core simulation engine with clean modular structure:

#### `src/models/` — Data Structures
Dataclasses representing entities in the system:
- **`device.py`** — `Device` class with identity attributes (device_id, type, resource_class, identity_method)
- **`token.py`** — `Token` class for authorization tokens with expiration, scope, and usage tracking
- **`session.py`** — `Session` class for MQTT sessions with connection metadata
- **`event.py`** — `Event` class representing a single record in the the ML dataset (34+ fields)

#### `src/core/` — Orchestration & State Management
Core simulation logic:
- **`state_machine.py`** — `StateMachine` and `LifecycleState` enum. Manages device lifecycle transitions (INIT → DISCOVERED → ... → TERMINATED)
- **`flow_engine.py`** — `FlowEngine` class orchestrating authentication flows. Manages devices, tokens, sessions, and state transitions
- **`event_generator.py`** — `EventGenerator` class creating Event objects from device/token/session state for dataset generation

#### `src/components/` — System Components
Simulated system entities:
- **`gateway.py`** — `Gateway` class simulating edge gateway. Performs device discovery, pairing, ACL checking, rate limiting
- **`auth_server.py`** — `AuthServer` class simulating cloud auth server. Manages device registry, token issuance, validation, revocation
- **`mqtt_broker.py`** — `MQTTBroker` class simulating MQTT broker. Handles CONNECT/DISCONNECT/PUBLISH, session management, message tracking

#### `src/scenarios/` — Attack & Normal Scenarios
High-level authentication flow simulations:
- **`normal_flow.py`** — `run_normal_flow()` function simulating legitimate device authentication from discovery to active messaging
- **`replay_attack.py`** — `run_replay_attack()` function simulating replay attacks (capture token, reuse after session ends)

#### `src/exporters/` — Data Export
Output formatters:
- **`csv_exporter.py`** — `CSVExporter` class exporting events to CSV with the retained feature columns
- **`json_exporter.py`** — `JSONExporter` class exporting events to JSON format

#### `src/utils/` — Utilities
Helper functions:
- **`time_utils.py`** — `TimeUtils` class with timestamp formatting utilities

### 📊 data/
Output directory for generated datasets:
- **`raw/`** — Input data directory (for future use)
- **`generated/`** — Generated datasets
  - `normal_events.csv` / `normal_events.json`
  - `replay_events.csv` / `replay_events.json`
  - `all_events.csv` / `all_events.json`

### 🧪 tests/
Unit tests:
- **`test_normal_flow.py`** — Tests for normal authentication flow (known devices, unknown devices, lifecycle phases)
- **`test_replay_attack.py`** — Tests for replay attack generation (basic attacks, anomaly markers, phase progression)

## Module Dependencies & Data Flow

```
main.py (Entry Point)
  ├─→ src/models/ (Device, Token, Session, Event)
  ├─→ src/core/ (FlowEngine, StateMachine, EventGenerator)
  ├─→ src/components/ (Gateway, AuthServer, MQTTBroker)
  ├─→ src/scenarios/ (normal_flow, replay_attack)
  └─→ src/exporters/ (CSVExporter, JSONExporter)
        └─→ data/generated/ (Output files)
```

**Flow:**
1. `main.py` creates devices and components
2. Passes them to scenarios (normal_flow, replay_attack)
3. Scenarios use FlowEngine to orchestrate authentication
4. EventGenerator creates Event objects representing each step
5. Events are exported to CSV/JSON by exporters
6. Tests validate scenarios work correctly

## How to Run This Module

### Quick Start
```bash
# Install dependencies
pip install -r requirements.txt

# Run simulator (generates all datasets)
python main.py

# Run tests
python tests/test_normal_flow.py
python tests/test_replay_attack.py
```

### Output
- Simulates 5 devices with normal and replay attack flows
- Generates ~400+ events total
- Creates 6 output files in `data/generated/`:
  - CSV files: easily opened in Excel, analyzable with pandas
  - JSON files: suitable for programmatic processing

## Code Organization Principles

1. **Models Layer**: Pure dataclasses, no business logic
2. **Core Layer**: State management and orchestration
3. **Components Layer**: System entity simulation
4. **Scenarios Layer**: High-level flow definitions
5. **Exporters Layer**: Output formatting

This separation allows:
- Easy testing of individual modules
- Simple addition of new scenarios
- Clean dependency injection
- Minimal coupling between layers

## Key Classes & Methods

### Device (`src/models/device.py`)
```python
device = Device(
    device_id="device_001",
    device_type="sensor",
    resource_class="constrained",
    identity_method="certificate"
)
```

### StateMachine (`src/core/state_machine.py`)
```python
sm = StateMachine()
sm.transition_to(LifecycleState.DISCOVERED)
current = sm.current_state
```

### FlowEngine (`src/core/flow_engine.py`)
```python
engine = FlowEngine()
engine.register_device(device)
token = engine.issue_token(device_id)
event = engine.generate_event(device_id)
```

### Scenarios
```python
# Normal flow
events = run_normal_flow(device, flow_engine, auth_server, mqtt_broker)

# Replay attack
events = run_replay_attack(device, flow_engine, auth_server, mqtt_broker)
```

### Export
```python
CSVExporter.export(events, Path("data/generated/events.csv"))
JSONExporter.export(events, Path("data/generated/events.json"))
```

### Prerequisites

- Python 3.8+
- pip package manager

### Installation

1. Navigate to the project directory:
   ```bash
   cd iot_auth_simulator
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Simulator

1. **Generate synthetic data** (main simulation):
   ```bash
   python main.py
   ```
   
   This will:
   - Simulate 5 devices
   - Run normal authentication flow for each device
   - Run replay attack scenario for each device
   - Generate CSV and JSON files in `data/generated/`:
     - `normal_events.csv` / `normal_events.json`
     - `replay_events.csv` / `replay_events.json`
     - `all_events.csv` / `all_events.json`

### Running Tests

1. **Run normal flow tests**:
   ```bash
   python tests/test_normal_flow.py
   ```

2. **Run replay attack tests**:
   ```bash
   python tests/test_replay_attack.py
   ```

### Viewing Generated Data

The generated CSV files can be opened in:
- Excel or LibreOffice Calc for spreadsheet analysis
- pandas/Python for programmatic analysis:
  ```python
  import pandas as pd
  df = pd.read_csv('data/generated/all_events.csv')
  print(df.describe())
  print(df[df['is_anomaly'] == True])
  ```

## Current Limitations

### Proof of Possession (PoP) - Deliberately Removed

For this MVP version, we have **intentionally removed** Proof of Possession (PoP) mechanisms to simplify the replay attack modeling:

- **No PoP fields**: `pop_check_passed`, `proof_of_possession` are NOT included
- **Simple token-based auth**: Tokens are validated only by ID and expiration
- **Replay attack feasibility**: Because PoP is removed, replay attacks with captured tokens are possible
- **Future enhancement**: PoP will be added in a future release to make replay attacks harder to execute

This design choice allows us to clearly model and detect replay attacks in the synthetic data.

## Future Enhancements

The following features are marked as TODO in the code and planned for future releases:

1. **Add PoP (Proof of Possession)**
   - Implement device signature verification
   - Add public/private key infrastructure
   - Make replay attacks detectable via PoP mismatch

2. **Implement additional attack scenarios**
   - `impersonation_attack.py`: Device impersonation attacks
   - `dos_attack.py`: Denial-of-Service and rate limiting bypass
   - `credential_stuffing.py`: Multiple device attacks with captured credentials

3. **Enhanced metrics**
   - Energy cost modeling for constrained devices
   - Realistic latency distributions based on network conditions
   - Resource consumption tracking

4. **ML baseline model**
   - Implement simple anomaly detection model (Isolation Forest, Autoencoders)
   - Evaluate detection performance on generated datasets
   - Provide baseline for model comparison

5. **Configuration-driven simulation**
   - Load device profiles from YAML
   - Parameterizable attack intensity and frequency
   - Scenario templates for different IoT deployments

6. **Advanced features**
   - Multi-gateway scenarios with load balancing
   - Token refresh and re-authentication flows
   - Rate limiting and throttling mechanisms
   - ACL violation detection

## Code Organization Philosophy

The project follows these design principles:

1. **Separation of Concerns**: Each module has a single responsibility
   - Models: Data structures only
   - Core: State management and orchestration
   - Components: System architecture pieces
   - Scenarios: High-level flows combining components
   - Exporters: Data output formatting

2. **Configurability**: Settings are centralized in `config/settings.yaml`

3. **Testability**: Scenarios and core logic can be tested independently

4. **Documentation**: Docstrings and comments explain intent and constraints

5. **Extensibility**: New scenarios and attack types can be added without modifying core

## Contributing

To extend the simulator:

1. **Add a new attack scenario**:
   - Create `src/scenarios/new_attack.py`
   - Import and call in `main.py`

2. **Add a new component**:
   - Create `src/components/new_component.py`
   - Integrate with scenarios

3. **Add export format**:
   - Create `src/exporters/new_format_exporter.py`
   - Call in `main.py`

## License

This project is provided as-is for research and educational purposes.

## Contact & Support

For questions or issues, please refer to the documentation comments in individual modules.

---

**Last Updated**: April 2026
**Version**: 0.1.0 (MVP)
**Status**: Active Development
