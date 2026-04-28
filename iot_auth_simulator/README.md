# IoT Authentication Flow Simulator

## Project Objective

This project is a **synthetic data generator** for training ML-based anomaly detection systems in IoT authentication flows. It simulates realistic device authentication lifecycles and generates labeled datasets with normal and anomalous events suitable for supervised machine learning.

## Key Features

- **Complete Authentication Lifecycle Simulation**: Models device discovery, pairing, enrollment, authorization, MQTT connection, and active session phases
- **Multiple Attack Scenarios**: Implements replay attack simulation to generate labeled anomalies
- **ML-Ready Dataset Export**: Generates CSV and JSON outputs with 34+ features for anomaly detection
- **Modular Architecture**: Clean separation of concerns (models, core, components, scenarios, exporters)
- **Configurable Parameters**: YAML-based configuration for device types, token expiration, MQTT settings
- **Unit Tests**: Includes basic tests for normal flow and replay attack scenarios
- **Comprehensive Logging**: Detailed logging for debugging and understanding simulation flow

## IoT Authentication Lifecycle

The simulator models a complete IoT device authentication flow with these phases:

```
INIT
  ↓
DISCOVERED (Device found via discovery protocol)
  ↓
PAIRED (Gateway/broker pairing established)
  ↓
ENROLLED (Device registered in auth server)
  ↓
AUTHORIZED (Token issued by auth server)
  ↓
MQTT_CONNECTED (MQTT CONNECT accepted)
  ↓
ACTIVE (Publishing/subscribing messages)
  ↓
TERMINATED (Session ended) or FAILED (Error state)
```

## System Architecture

### Components

1. **Device Model**: Represents constrained IoT devices with identity attributes
   - `device_id`: Unique identifier
   - `device_type`: sensor, actuator, gateway, controller
   - `resource_class`: constrained, moderate, high_capability
   - `identity_method`: certificate, preshared_key, username_password
   - `known_to_registry`: Boolean flag for enrollment success

2. **Edge/Gateway**: Performs device discovery, pairing, ACL enforcement, rate limiting
   - Discovery (simulated mDNS/CoAP)
   - Pairing with devices
   - ACL checking for topic operations
   - Rate limiting enforcement

3. **Cloud/Auth Server**: Issues and validates tokens, manages device registry
   - Device registration
   - Token issuance with expiration
   - Token validation and revocation
   - Policy management

4. **MQTT Broker**: Handles CONNECT, DISCONNECT, and PUBLISH operations
   - CONNECT validation (checks token validity)
   - Session management
   - Message receipt and routing

### Data Flow

```
Device → Discovery → Gateway → Pairing → Auth Server → Token Issue
                                            ↓
                                        Token Valid?
                                            ↓ YES
                                        MQTT Broker → CONNECT Accept
                                            ↓
                                        Session Active
                                            ↓
                                        PUBLISH Messages
```

## Generated Dataset Fields

### Device Identity
- `device_id`: Unique device identifier
- `device_type`: Type of device (sensor, actuator, gateway, controller)
- `resource_class`: Resource capability class (constrained, moderate, high_capability)
- `identity_method`: Authentication method (certificate, preshared_key, username_password)
- `known_to_registry`: Boolean indicating if device is pre-registered

### Temporal & Lifecycle
- `timestamp`: ISO 8601 timestamp of the event
- `lifecycle_phase`: Current authentication phase (DISCOVERED, PAIRED, ENROLLED, etc.)
- `auth_method`: Authentication method used for this phase
- `auth_result`: Success or failure of authentication attempt
- `auth_duration_ms`: Time taken for authentication in milliseconds

### Token Information
- `token_id`: Unique identifier for the authorization token
- `token_valid`: Boolean indicating if token is still valid
- `token_expired`: Boolean indicating if token has expired
- `token_scope`: Authorization scope (e.g., "sensors/temperature,sensors/humidity")

### TLS & Security
- `tls_enabled`: Boolean indicating if TLS is enabled

### MQTT Connection
- `mqtt_version`: MQTT protocol version (3, 4, or 5)
- `qos_level`: Quality of Service level (0, 1, or 2)
- `mqtt_conack_val`: MQTT CONNACK return code (0=accepted, 1-5=failures)
- `clean_session_flag`: Boolean for session cleanup preference
- `keep_alive_s`: Keep-alive interval in seconds

### Topic & Authorization
- `requested_topic`: MQTT topic device is trying to access
- `topic`: Topic for current publish/subscribe
- `token_scope_match`: Boolean indicating if token scope matches requested topic
- `acl_match`: Boolean indicating if device ACL allows the operation

### Message/Connection Metrics
- `message_frequency`: Messages per second during connection
- `payload_size_bytes`: Size of message payload in bytes
- `latency_ms`: Connection latency in milliseconds
- `connection_duration_s`: How long the connection has been active in seconds
- `duplicate_message_flag`: Boolean indicating duplicate message detection

### Anomaly Indicators
- `message_frequency_anomaly_flag`: Boolean for abnormally high message frequency
- `latency_anomaly_flag`: Boolean for abnormally high latency
- `is_anomaly`: Primary label for anomaly detection (True/False)

### Attack Information
- `attack_type`: Type of attack ("" for normal, "replay", "impersonation", etc.)
- `attacker_type`: Category of attacker ("" for normal, "non-invasive", "invasive", etc.)

## Project Structure

```
iot_auth_simulator/
│
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── main.py                   # Main entry point
│
├── config/
│   └── settings.yaml         # Configuration parameters
│
├── src/
│   ├── __init__.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── device.py         # Device dataclass
│   │   ├── session.py        # MQTT session dataclass
│   │   ├── token.py          # Authorization token dataclass
│   │   └── event.py          # Event/record for ML dataset
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── state_machine.py  # Lifecycle state machine
│   │   ├── flow_engine.py    # Orchestrates authentication flows
│   │   └── event_generator.py# Generates events from states
│   │
│   ├── components/
│   │   ├── __init__.py
│   │   ├── gateway.py        # Edge gateway component
│   │   ├── auth_server.py    # Auth server component
│   │   └── mqtt_broker.py    # MQTT broker component
│   │
│   ├── scenarios/
│   │   ├── __init__.py
│   │   ├── normal_flow.py    # Normal authentication scenario
│   │   └── replay_attack.py  # Replay attack scenario
│   │
│   ├── exporters/
│   │   ├── __init__.py
│   │   ├── csv_exporter.py   # Export events to CSV
│   │   └── json_exporter.py  # Export events to JSON
│   │
│   └── utils/
│       ├── __init__.py
│       └── time_utils.py     # Time utility functions
│
├── data/
│   ├── raw/                  # Raw input data (if needed)
│   └── generated/            # Generated datasets
│       ├── normal_events.csv
│       ├── normal_events.json
│       ├── replay_events.csv
│       ├── replay_events.json
│       ├── all_events.csv
│       └── all_events.json
│
└── tests/
    ├── test_normal_flow.py   # Tests for normal flow
    └── test_replay_attack.py # Tests for replay attacks
```

## How to Run

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
