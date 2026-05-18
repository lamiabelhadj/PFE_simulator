# Future Modifiable Variables Guide

This document guides future developers on **what variables can be modified** to customize the IoT authentication simulator. All modifiable variables relate directly to simulator functionality and dataset generation.

---

## Table of Contents
1. [Configuration File Variables](#configuration-file-variables)
2. [Main Entry Point Parameters](#main-entry-point-parameters)
3. [Device Simulation Parameters](#device-simulation-parameters)
4. [Authentication Settings](#authentication-settings)
5. [Data Export Settings](#data-export-settings)
6. [How to Modify Variables](#how-to-modify-variables)
7. [Tips for Extension](#tips-for-extension)

---

## Configuration File Variables

### Location
📁 **File**: `config/settings.yaml`

This is the **primary configuration file** for all simulator settings. Modify values here to control simulator behavior without changing code.

### Simulator Parameters

```yaml
simulator:
  num_devices: 20                    # Number of IoT devices to simulate (range: 1-1000)
  normal_events_per_device: 5        # Events per device in normal flow (range: 1-100)
  replay_events_per_device: 2        # Events per device in replay attack (range: 0-50)
```

**What these control:**
- `num_devices`: Total number of virtual IoT devices created in the simulation
- `normal_events_per_device`: How many normal authentication/communication events each device generates
- `replay_events_per_device`: How many replay attack events are simulated per device

**Example adjustments:**
- ⬆️ **Increase** `num_devices` to generate **larger datasets**
- ⬆️ **Increase** `normal_events_per_device` for **more normal samples** (less anomaly ratio)
- ⬆️ **Increase** `replay_events_per_device` for **more attack samples** (higher anomaly ratio)

---

### Device Configuration

```yaml
device:
  types:
    - "sensor"           # IoT device that collects data
    - "actuator"         # Device that performs actions
    - "gateway"          # Edge device connecting to cloud
    - "controller"       # Central control device
  
  resource_classes:
    - "constrained"      # Limited CPU/memory (e.g., embedded devices)
    - "moderate"         # Medium resources (e.g., RPi)
    - "high_capability"  # Powerful devices (e.g., industrial gateways)
  
  identity_methods:
    - "preshared_key"    # Pre-shared symmetric key authentication
    - "username_password" # Traditional username/password auth
```

**What these control:**
- **types**: Device diversity in the simulated environment (affects behavior patterns)
- **resource_classes**: Capability levels that influence authentication complexity
- **identity_methods**: Authentication mechanisms each device can use

**How to modify:**
- ✏️ **Add new device types** to simulate additional IoT categories (e.g., "wearable")
- ✏️ **Add new resource classes** for different capability tiers (e.g., "ultra_constrained")
- ✏️ **Add new identity methods** to test different authentication schemes (e.g., "certificate")

**⚠️ Important**: After adding new values:
1. Update corresponding logic in `src/core/event_generator.py`
2. Update device generation logic in `src/models/device.py`
3. Update dataset export to include new attributes in `src/exporters/`

---

### Authentication Settings

```yaml
auth:
  token_expiration_s: 3600  # Token lifetime in seconds (e.g., 3600 = 1 hour)
  tls_enabled: true         # Enable/disable TLS encryption
```

**What these control:**
- `token_expiration_s`: How long authentication tokens remain valid
- `tls_enabled`: Whether encrypted channels are used

**Example adjustments:**
- ⬇️ **Decrease** `token_expiration_s` to simulate **frequent re-authentication** (0-3600 seconds)
- 🔒 **Toggle** `tls_enabled` to test **encrypted vs. unencrypted scenarios**

---

### MQTT Broker Settings

```yaml
mqtt:
  broker_host: "mqtt.cloud.example.com"  # MQTT broker address
  
  versions:      # Supported MQTT protocol versions
    - 3          # MQTT 3.1
    - 4          # MQTT 3.1.1
    - 5          # MQTT 5.0
  
  qos_levels:    # Quality of Service levels
    - 0           # At most once (fire and forget)
    - 1           # At least once (acknowledgment required)
    - 2           # Exactly once (guaranteed delivery)
```

**What these control:**
- `broker_host`: Target MQTT broker endpoint
- `versions`: Protocol versions used by simulated devices
- `qos_levels`: Message delivery guarantees available

**How to modify:**
- 🔄 **Update** `broker_host` to point to a different MQTT broker
- ✏️ **Add/remove MQTT versions** to test compatibility scenarios
- ✏️ **Add/remove QoS levels** to test different reliability modes

---

### Data Export Settings

```yaml
export:
  output_dir: "data/generated"  # Where to save generated datasets
  
  formats:        # Export data formats
    - "csv"       # Comma-separated values (spreadsheet-friendly)
    - "json"      # JSON format (hierarchical data)
```

**What these control:**
- `output_dir`: Directory where all generated event files are saved
- `formats`: Output formats for the dataset

**Example adjustments:**
- 📁 **Change** `output_dir` to export to different location
- ✏️ **Add new formats** (e.g., "parquet" for big data tools)

---

## Main Entry Point Parameters

### Location
📁 **File**: `main.py`

The main entry point allows command-line parameter overrides:

```python
# In main.py
result = run_simulation(SimulationOptions(num_devices=5))
```

**What you can modify:**
- `num_devices`: Override the config file value for this specific run

**Example:**
```python
# Simulate 100 devices instead of config value
result = run_simulation(SimulationOptions(num_devices=100))
```

---

## Device Simulation Parameters

### Location
📁 **File**: `src/models/device.py`

Device attributes control individual device characteristics:

```python
@dataclass
class Device:
    device_id: str                          # Unique device identifier
    device_type: str                        # From config: sensor, actuator, gateway, controller
    resource_class: str                     # From config: constrained, moderate, high_capability
    identity_method: str                    # From config: preshared_key, username_password
    known_to_registry: bool = True          # Is device registered? (affects behavior)
    mac_address: str = ""                   # Device MAC address
    firmware_version: str = "1.0.0"         # Device firmware version
    created_at: datetime = field(...)       # Device creation timestamp
```

**What you can customize:**
- `firmware_version`: Change default firmware version for devices
- `known_to_registry`: Toggle to test registered vs. unregistered devices
- Add new device attributes (e.g., `location: str`, `security_level: int`)

**Example modifications:**
```python
# Add a new device attribute for location tracking
location: str = "datacenter-1"

# Add security capability level
security_level: int = 1  # 1=basic, 2=enhanced, 3=advanced
```

---

## Authentication Settings

### Location
📁 **File**: `src/core/event_generator.py` & `config/settings.yaml`

Control authentication behavior through event generation:

```python
def generate_event(
    self,
    device: Device,
    lifecycle_phase: LifecycleState,
    token: Optional[Token] = None,
    session: Optional[Session] = None,
    is_anomaly: bool = False,           # Mark event as anomalous
    attack_type: str = "",              # Type of attack (if anomalous)
    attacker_type: str = "",            # Who's attacking
) -> Event:
```

**What you can modify:**
- `attack_type`: Add new attack scenarios (e.g., "man_in_the_middle", "credential_stuffing")
- `attacker_type`: Define different attacker profiles (e.g., "insider", "external", "automated")
- Token expiration logic in `src/models/token.py`
- Session behavior in `src/models/session.py`

**Example: Adding new attack types**
1. Update `replay_attack.py` to generate new attack patterns
2. Extend `event_generator.py` to handle new attack_type values
3. Update export to include new attack classifications

---

## Data Export Settings

### Location
📁 **File**: `src/exporters/csv_exporter.py` & `src/exporters/json_exporter.py`

Control what data is exported and how:

**CSV Export** (`csv_exporter.py`):
- Modify which event attributes are included
- Change column ordering
- Customize CSV headers

**JSON Export** (`json_exporter.py`):
- Modify JSON structure
- Add/remove nested fields
- Customize serialization

**Example modification:**
```python
# In csv_exporter.py - add new column
columns = ['timestamp', 'device_id', 'event_type', 'NEW_COLUMN_NAME', ...]

# In json_exporter.py - add new nested data
event_dict = {
    'basic_info': {...},
    'security_context': {...},
    'new_section': {...}  # NEW
}
```

---

## How to Modify Variables

### Safe Modification Steps

#### Option 1: Configuration File 
1. ✏️ Open `config/settings.yaml`
2. 📝 Edit numeric values, lists, or strings
3. 💾 Save the file
4. ▶️ Run `python main.py` - changes apply automatically

**Safest to modify:**
- `num_devices`, `normal_events_per_device`, `replay_events_per_device`
- `token_expiration_s`
- `output_dir`

#### Option 2: Main Entry Point (For specific runs)
1. ✏️ Edit `main.py`
2. 📝 Change `SimulationOptions(num_devices=X)`
3. 💾 Save the file
4. ▶️ Run `python main.py`

#### Option 3: Source Code Modifications 
1. ✏️ Edit source files in `src/`
2. 🧪 Update tests in `tests/`
3. 🧪 Run tests: `pytest tests/`
4. 💾 Commit changes to version control

### Validation After Modification

After modifying variables:

```bash
# Run tests to validate changes
pytest tests/

# Check that simulation runs without errors
python main.py

# Verify output files are generated
ls data/generated/
```

---

## Tips for Extension

### Adding New Device Types

**Steps:**
1. Add to `config/settings.yaml` under `device.types`
2. Update device creation logic in `src/simulator_runner.py`
3. Define type-specific behavior in `src/components/gateway.py`
4. Add tests in `tests/test_*.py`

### Adding New Attack Scenarios

**Steps:**
1. Create new file in `src/scenarios/` (e.g., `dos_attack.py`)
2. Implement attack pattern generation
3. Update `simulator_runner.py` to include new scenario
4. Add event generation logic in `event_generator.py`
5. Export new attack type in exporters

### Adding New Features to Events

**Steps:**
1. Add fields to `src/models/event.py`
2. Update event population in `event_generator.py`
3. Update CSV/JSON exporters to include new fields
4. Update tests with new field validations

### Creating Derived Datasets

**Example: Generate unbalanced dataset**
```python
# In main.py
result = run_simulation(SimulationOptions(
    num_devices=100,
    normal_events_per_device=50,    # Many normal events
    replay_events_per_device=1      # Few anomalies
))
```

**Example: Test specific scenario**
```python
# Modify config or use command-line parameters
# Run only normal flow for baseline dataset
# Run only replay attacks for attack analysis
```

---

## Quick Reference Table

| Variable | File | Type | Impact | Safe to Modify |
|----------|------|------|--------|----------------|
| `num_devices` | config/settings.yaml | Integer | Dataset size | ✅ Yes |
| `normal_events_per_device` | config/settings.yaml | Integer | Event count | ✅ Yes |
| `replay_events_per_device` | config/settings.yaml | Integer | Anomaly ratio | ✅ Yes |
| `device.types` | config/settings.yaml | List | Device diversity | ⚠️ Requires code changes |
| `token_expiration_s` | config/settings.yaml | Integer | Auth behavior | ✅ Yes |
| `tls_enabled` | config/settings.yaml | Boolean | Encryption | ✅ Yes |
| `output_dir` | config/settings.yaml | String | Export location | ✅ Yes |
| `attack_type` | event_generator.py | String | Attack patterns | ⚠️ Requires code changes |
| `device_type` | models/device.py | String | Device attributes | ⚠️ Requires code changes |

---

## Need Help?

- 📖 Read the [README.md](README.md) for project overview
- 🔍 Check `src/` for implementation details
- 🧪 Review `tests/` for usage examples
- 📊 Inspect `data/generated/` for sample output

---

**Last Updated**: 2026-05-18
**Target Users**: Future developers extending or customizing the simulator
