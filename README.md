# IoT Authentication Flow Simulator  
### Synthetic Data Generation for Anomaly Detection

---

## 📌 Project Overview

This project implements a **simulation framework for IoT authentication flows** with the objective of generating **realistic synthetic datasets** for **anomaly detection in cybersecurity**.

The simulator models the complete lifecycle of an IoT device authentication process and injects controlled attack scenarios to produce **labeled data suitable for ML-based detection systems**.

### Key Features
- ✅ Complete authentication lifecycle simulation (Discovery → Pairing → Enrollment → Authorization → MQTT Session)
- ✅ Multiple attack scenarios (Replay attacks, with extensibility for impersonation & DoS)
- ✅ ML-ready dataset export (CSV & JSON formats)
- ✅ Fully labeled events with 34+ features
- ✅ Modular architecture for easy extension
- ✅ Comprehensive logging and debugging capabilities

---

## 🎯 Objectives

- Model a **realistic IoT authentication lifecycle**
- Simulate **normal and anomalous behaviors**
- Generate **structured labeled datasets**
- Support **anomaly detection (IDS / ML models)**
- Provide a foundation for testing **ML-based security systems**

---

## 🧠 Core Concept

Real-world IoT security datasets are:
- **Scarce** — difficult to obtain in real deployments
- **Imbalanced** — anomalies are rare in production
- **Difficult to label** — require expert annotation
- **Privacy-sensitive** — contain sensitive device/user data

👉 **This simulator addresses these challenges by generating:**
- **Controlled scenarios** — reproducible attack patterns
- **Fully labeled events** — no annotation needed
- **Balanced datasets** — adjustable anomaly ratios
- **Synthetic data** — privacy-preserving

---

## 🏗️ Architecture Overview

The system is based on a **3-layer architecture**:

### 🔹 Layer 1 — IoT Device
Simulates constrained IoT devices with:
- Limited computational resources
- Pre-shared identity credentials
- Lifecycle state management

**Authentication phases:**
- Discovery (device detection)
- Pairing (key exchange)
- Enrollment (identity registration)
- Authorization (token acquisition)
- MQTT session (connection & messaging)
- Re-authentication (token refresh)

**Device attributes:**
- `device_id`: Unique identifier
- `device_type`: sensor, actuator, gateway, controller
- `resource_class`: constrained, moderate, high_capability
- `identity_method`: certificate, preshared_key, username_password

---

### 🔹 Layer 2 — Edge / Gateway (Core Layer)
Central orchestration component of the system.

**Key Responsibilities:**
- 🔐 Authentication proxy between device and cloud
- ✅ Authorization checks (ACL enforcement)
- 📋 MQTT topic-based access control
- ⏱️ Rate limiting per device
- 🔍 Anomaly observation & event labeling
- 📊 Traffic aggregation & metrics

👉 **This is the primary observation point for anomaly detection** — all authentication attempts and message flows are logged here with rich contextual information.

---

### 🔹 Layer 3 — Cloud / Backend
- 🔑 Authorization Server (OAuth2 / ACE compatible)
- 📋 Policy repository
- 💾 Dataset storage
- 🤖 ML training & evaluation infrastructure

---

## 🔐 Authentication Model

### Current Implementation (MVP)
- **Key exchange**: ECDH-based (pairing phase)
- **Identity mechanism**: Pre-Shared Key (PSK) — simplified for MVP
- **Authorization**: Token-based (OAuth2 / ACE compatible)
- **Transport Security**: MQTT over TLS

### Session Management
- Token expiration: 1 hour (configurable)
- Session tracking: per device-token pair
- Re-authentication: automatic on token expiration

⚠️ **Important Design Decision**
- **Proof of Possession (PoP) is intentionally removed in MVP**
- This allows clearer modeling of **replay attack scenarios**
- PoP will be added in future releases for stronger security

---

## 🔄 Authentication Lifecycle States

The simulator models the full device lifecycle:

```
INIT
  ↓
DISCOVERED (mDNS/CoAP discovery)
  ↓
PAIRED (Gateway pairing established)
  ↓
ENROLLED (Device registered in auth server)
  ↓
AUTHORIZED (Token issued by auth server)
  ↓
MQTT_CONNECTED (MQTT CONNECT accepted)
  ↓
ACTIVE (Publishing/subscribing messages)
  ↓
REAUTH_REQUIRED (Token expiring)
  ↓
TERMINATED (Session ended gracefully)

Can transition to FAILED at any phase
```

---

## 🚨 Threat Model & Attack Scenarios

The simulator supports multiple attack types:

### 🎯 Priority Scenarios (Current/MVP)
- ✅ **Replay Attack** — Reuse of captured valid tokens after session termination
- 🔄 **In Progress**: Impersonation, DoS/Flood scenarios

### 🔮 Extended Scenarios (Planned)
- Rogue device injection
- Protocol downgrade attacks
- Node capture & credential extraction
- On-off attacks (intermittent malicious behavior)
- Credential stuffing across devices

---

## 🔁 Replay Attack Deep Dive

**What is a replay attack?**
Reuse of a previously captured and valid authentication element (e.g., token) after the original session ends.

**Attack Flow in Simulator:**
1. Device performs normal authentication → receives valid token
2. Attacker captures the token ID
3. Original session is terminated
4. Attacker attempts MQTT connection using captured token
5. Result depends on token state:
   - If **expired** → Connection fails (auth_result = "fail")
   - If **already used** → Connection fails + duplicate flag set
   - If **still valid** → Connection succeeds (marked as anomaly)

**Detection Signals Generated:**
- `duplicate_message_flag`: True when token reused
- `message_frequency_anomaly_flag`: Higher frequency during attack
- `latency_anomaly_flag`: Abnormal latency patterns
- `is_anomaly`: Primary label (True)
- `attack_type`: "replay"
- `attacker_type`: "non-invasive"

**Why PoP Removal Matters:**
Without Proof of Possession verification, replay attacks are possible with just token capture. This is intentional for MVP to model and detect this specific threat clearly.

---

## 📊 Generated Dataset Features

Each simulation produces structured records with 34+ features:

### Device Identity Features (5 fields)
- `device_id`: Unique device identifier
- `device_type`: Type of device
- `resource_class`: Resource capability
- `identity_method`: Authentication method
- `known_to_registry`: Registration status

### Temporal & Lifecycle Features (5 fields)
- `timestamp`: Event timestamp (ISO 8601)
- `lifecycle_phase`: Current authentication phase
- `auth_method`: Authentication method used
- `auth_result`: "success" or "fail"
- `auth_duration_ms`: Authentication latency

### Token & Security Features (4 fields)
- `token_id`: Authorization token identifier
- `token_valid`: Token validity status
- `token_expired`: Token expiration status
- `token_scope`: Token authorization scope

### TLS/Transport Features (1 field)
- `tls_enabled`: TLS security status

### MQTT Connection Features (5 fields)
- `mqtt_version`: Protocol version (3, 4, or 5)
- `qos_level`: Quality of Service level
- `mqtt_conack_val`: Connection acknowledgment code
- `clean_session_flag`: Session restart preference
- `keep_alive_s`: Keep-alive interval

### Topic & Authorization Features (4 fields)
- `requested_topic`: Target MQTT topic
- `topic`: Message topic
- `token_scope_match`: Scope-topic alignment
- `acl_match`: ACL enforcement result

### Message/Connection Metrics (6 fields)
- `message_frequency`: Messages per second
- `payload_size_bytes`: Message size
- `latency_ms`: Network latency
- `connection_duration_s`: Session duration
- `duplicate_message_flag`: Duplicate detection
- `message_frequency_anomaly_flag`: Abnormal frequency

### Anomaly Indicators (3 fields)
- `latency_anomaly_flag`: Abnormal latency
- `is_anomaly`: Primary anomaly label
- `attack_type`: "replay", "impersonation", or ""

### Attack Information (1 field)
- `attacker_type`: "non-invasive", "invasive", or ""

---

## 📁 Project Structure

```
PFE_simulator/
│
├── README.md                          # Global project documentation
│
├── iot_auth_simulator/                # Main simulator package
│   │
│   ├── README.md                      # Detailed simulator documentation
│   ├── requirements.txt               # Python dependencies
│   ├── main.py                        # Entry point
│   │
│   ├── config/
│   │   └── settings.yaml              # Configuration parameters
│   │
│   ├── src/
│   │   ├── models/                    # Data structures
│   │   │   ├── device.py              # Device representation
│   │   │   ├── token.py               # Authorization token
│   │   │   ├── session.py             # MQTT session
│   │   │   └── event.py               # ML dataset record
│   │   │
│   │   ├── core/                      # Core orchestration
│   │   │   ├── state_machine.py       # Lifecycle state management
│   │   │   ├── flow_engine.py         # Authentication flow orchestration
│   │   │   └── event_generator.py     # Event generation
│   │   │
│   │   ├── components/                # System components
│   │   │   ├── gateway.py             # Edge/Gateway simulation
│   │   │   ├── auth_server.py         # Cloud auth server
│   │   │   └── mqtt_broker.py         # MQTT broker
│   │   │
│   │   ├── scenarios/                 # Attack scenarios
│   │   │   ├── normal_flow.py         # Normal authentication
│   │   │   └── replay_attack.py       # Replay attack scenario
│   │   │
│   │   ├── exporters/                 # Data export
│   │   │   ├── csv_exporter.py        # CSV output
│   │   │   └── json_exporter.py       # JSON output
│   │   │
│   │   └── utils/                     # Utilities
│   │       └── time_utils.py          # Time utilities
│   │
│   ├── data/
│   │   ├── raw/                       # Input data (if needed)
│   │   └── generated/                 # Generated datasets
│   │       ├── normal_events.csv
│   │       ├── replay_events.csv
│   │       └── all_events.csv
│   │
│   └── tests/                         # Unit tests
│       ├── test_normal_flow.py        # Normal flow tests
│       └── test_replay_attack.py      # Replay attack tests
│
└── .vscode/
    └── tasks.json                     # VS Code run tasks
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

```bash
cd iot_auth_simulator
pip install -r requirements.txt
```

### Running the Simulator

```bash
python main.py
```

**Output:**
- Simulates 5 devices with normal and replay attack scenarios
- Generates 3 CSV files:
  - `data/generated/normal_events.csv`
  - `data/generated/replay_events.csv`
  - `data/generated/all_events.csv`
- Also exports JSON format

### Running Tests

```bash
# Test normal flow
python tests/test_normal_flow.py

# Test replay attack
python tests/test_replay_attack.py
```

---

## 📈 Dataset Analysis

### Using Pandas
```python
import pandas as pd

# Load dataset
df = pd.read_csv('iot_auth_simulator/data/generated/all_events.csv')

# Explore
print(f"Total events: {len(df)}")
print(f"Anomalies: {df['is_anomaly'].sum()}")
print(f"Attack types: {df['attack_type'].unique()}")

# Filter anomalies
anomalies = df[df['is_anomaly'] == True]
print(f"\nAnomaly distribution:")
print(anomalies['attack_type'].value_counts())
```

### Dataset Statistics
- **Normal events**: ~35-40 events per device
- **Replay events**: ~15-20 events per device per attack scenario
- **Anomaly ratio**: ~30-40% (configurable)
- **Total features**: 34+

---

## 🔬 Use Cases

### 1. **ML Model Development**
- Train anomaly detection classifiers
- Baseline models: Isolation Forest, Autoencoders, XGBoost
- Evaluate IDS/IPS systems

### 2. **Security Research**
- Study IoT authentication vulnerabilities
- Simulate novel attack patterns
- Validate detection mechanisms

### 3. **Threat Modeling**
- Design defense strategies
- Test edge gateway configurations
- Evaluate token expiration policies

### 4. **Dataset Benchmarking**
- Compare detection algorithms
- Establish performance baselines
- Publish results in peer-reviewed venues

---

## 🎯 Future Enhancements

### Short-term (v0.2)
- [ ] Add Proof of Possession (PoP) implementation
- [ ] Implement impersonation attack scenario
- [ ] Add DoS/flooding scenario
- [ ] ML baseline anomaly detection model

### Medium-term (v0.3)
- [ ] Configuration-driven simulation
- [ ] Multi-gateway scenarios
- [ ] Advanced latency modeling
- [ ] Energy consumption tracking

### Long-term (v1.0)
- [ ] Real device integration
- [ ] MQTT protocol extensions
- [ ] Advanced threat scenarios
- [ ] Web-based visualization dashboard

---

## 📚 Documentation

- **Main Simulator**: See `iot_auth_simulator/README.md` for detailed architecture
- **Code Documentation**: All modules have comprehensive docstrings
- **Configuration**: Edit `iot_auth_simulator/config/settings.yaml` for parameters

---

## 🤝 Contributing

To extend the simulator:

1. **Add new attack scenarios**: Create `src/scenarios/your_attack.py`
2. **Add components**: Create `src/components/your_component.py`
3. **Add exporters**: Create `src/exporters/your_exporter.py`
4. **Write tests**: Add tests in `tests/` directory

---

## 📄 License

This project is provided for research and educational purposes.

---

## 📞 Support

For questions, issues, or suggestions:
- Review code documentation in modules
- Check existing tests for usage examples
- Refer to `iot_auth_simulator/README.md` for detailed information

---

## 📝 Citation

If you use this simulator in research, please acknowledge:

```
IoT Authentication Flow Simulator
A framework for generating synthetic labeled datasets for anomaly detection
in IoT authentication flows.
```

---

**Status**: Active Development  
**Version**: 0.1.0 (MVP)  
**Last Updated**: April 2026
