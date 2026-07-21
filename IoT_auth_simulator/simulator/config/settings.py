"""
config/settings.py
──────────────────
Central configuration for the IoT Authentication Simulator.
 Import with:

    from config.settings import SimulationConfig, NetworkConfig, ...
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data" / "output"
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# 1.  Simulation control
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SimulationConfig:
    """Top-level knobs for the simulation runner."""

    # Reproducibility
    random_seed: int = 42

    # Volume
    num_devices:          int = 200    # total IoT devices to simulate
    num_sessions_normal:  int = 1000    # benign authentication sessions
    num_sessions_attack:  int = 100   # malicious sessions (split across attack types)

    # Attack type distribution (must sum to 1.0)
    attack_distribution: Dict[str, float] = field(default_factory=lambda: {
        "replay_token":            0.10,
        "nonce_reuse":             0.10,
        "timestamp_inconsistency": 0.10,
        "duplicate_sequence":      0.10,
        "impersonation":           0.10,
        "identity_token_mismatch": 0.10,
        "access_without_auth":     0.10,
        "abnormal_failure_rate":   0.09,
        "abnormal_renewal":        0.07,
        "connect_flood":           0.07,
        "delayed_connect":         0.07,
    })

    # Gateway pool size
    num_gateways: int = 5

    # Phase C — drive the real core/ domain entities (Device, Gateway,
    # AuthServer, MQTTBroker) during generation so ECDH / token issuance /
    # validation and broker sessions are exercised end-to-end. Off by default:
    # when off, generation is byte-for-byte the synthesised pipeline; when on,
    # the entities are exercised and the emitted token id is the one the
    # AuthServer actually minted, but the leakage-tuned feature values are
    # unchanged.
    wire_entities: bool = False

    # Output
    output_filename: str = "iot_auth_dataset.csv"


# ══════════════════════════════════════════════════════════════════════════════
# 2.  Network / topology
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkConfig:
    """IP ranges and connectivity parameters."""

    # Simulated subnets
    device_subnet:  str = "10.0.1."      # device IPs: 10.0.1.{1..254}
    gateway_ip:     str = "192.168.1.1"
    auth_server_ip: str = "10.10.0.10"
    broker_ip:      str = "10.10.0.20"

    # Latency profiles (milliseconds) — sampled with Gaussian noise
    latency_normal_mean_ms:  float = 45.0
    latency_normal_std_ms:   float = 10.0
    latency_attack_mean_ms:  float = 8.0    # attackers are often faster / more aggressive
    latency_attack_std_ms:   float = 30.0

    # Packet rates (packets/sec)
    packet_rate_normal_mean: float = 5.0
    packet_rate_normal_std:  float = 1.5
    packet_rate_dos_mean:    float = 350.0
    packet_rate_dos_std:     float = 80.0

    # TCP RTT (ms)
    rtt_normal_mean_ms: float = 20.0
    rtt_normal_std_ms:  float = 5.0


# ══════════════════════════════════════════════════════════════════════════════
# 3.  Device profiles
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DeviceConfig:
    """Parameters that characterise an IoT device."""

    # Battery level range (%)
    battery_min: float = 5.0
    battery_max: float = 100.0

    # PSK (pre-shared key) byte length
    psk_length_bytes: int = 32

    # Device types available in the simulation
    device_types: List[str] = field(default_factory=lambda: [
        "sensor",
        "actuator",
        "gateway_client",
        # "camera",
        # "smart_meter",
    ])

    # Firmware versions reported by devices (categorical event-log feature)
    firmware_versions: List[str] = field(default_factory=lambda: [
        "1.0.4", "1.2.0", "1.4.2", "2.0.1", "2.1.3", "2.3.0", "3.0.0",
    ])

    # Keep-alive window (seconds) for MQTT
    keep_alive_normal_s: int = 60
    keep_alive_short_s:  int = 10    # suspicious / attack pattern


# ══════════════════════════════════════════════════════════════════════════════
# 4.  Security / cryptography
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityConfig:
    """Cryptographic and Zero-Trust parameters."""

    # ECDH curve used during Pairing step
    ecdh_curve: str = "secp256r1"

    # OAuth2 / ACE token lifetime (seconds)
    token_lifetime_s:       int = 300    # 5 minutes — normal
    token_lifetime_short_s: int = 30     # aggressive re-auth / attacker

    # Replay attack — how old a captured token can be (seconds)
    replay_window_s: int = 120

    # Trust score boundaries (0.0 = untrusted, 1.0 = fully trusted)
    trust_score_initial:   float = 0.8
    trust_score_threshold: float = 0.5   # below this → re-auth required

    # Max failed auth attempts before flagging
    max_failed_auth: int = 3

    # ABAC / Zero Trust — continuous verification interval (seconds)
    reauth_interval_s: int = 60


# ══════════════════════════════════════════════════════════════════════════════
# 5.  MQTT session
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MQTTConfig:
    """MQTT v5 session parameters."""

    # Protocol version simulated
    mqtt_version: List[int] = field(default_factory=lambda: [3, 4, 5])

    # QoS levels available
    qos_levels: List[int] = field(default_factory=lambda: [0, 1, 2])

    # Normal payload size range (bytes)
    payload_size_min: int = 10
    payload_size_max: int = 512

    # DoS payload size (bytes) — oversized to stress broker
    payload_size_dos_max: int = 65535

    # Topic structure
    topic_prefix:   str = "iot"
    topic_max_depth: int = 4

    # Session duration range (seconds)
    session_duration_min_s: int  = 30
    session_duration_max_s: int  = 600

    # Message rate (msgs/sec) — normal vs flood
    msg_rate_normal_mean: float = 1.0
    msg_rate_normal_std:  float = 0.3
    msg_rate_flood_mean:  float = 500.0


# ══════════════════════════════════════════════════════════════════════════════
# 6.  Attack-specific parameters
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackConfig:
    """Fine-grained control over each attack module."""

    # Replay Attack
    replay_token_age_min_s: int = 5
    replay_token_age_max_s: int = 300

    # Impersonation Attack
    # Probability that attacker uses a *slightly* different IP
    impersonation_ip_change_prob: float = 0.6

    # DoS / Flooding
    dos_connection_burst:    int   = 50    # simultaneous connections (CONNECT flood)
    dos_duration_s:          float = 10.0  # flood window
    delayed_connect_stall_s: float = 30.0  # half-open CONNECT hold time (mean)

    # Severity mapping per attack type
    severity_map: Dict[str, str] = field(default_factory=lambda: {
        "replay_token":            "medium",
        "nonce_reuse":             "medium",
        "timestamp_inconsistency": "medium",
        "duplicate_sequence":      "medium",
        "impersonation":           "high",
        "identity_token_mismatch": "high",
        "access_without_auth":     "high",
        "abnormal_failure_rate":   "high",
        "abnormal_renewal":        "medium",
        "connect_flood":           "high",
        "delayed_connect":         "high",
    })

    # Attacker-class taxonomy per attack type (functional-model threat model):
    #   non_invasive — network-layer attacker, no valid credentials
    #   invasive     — holds valid credentials (compromised device)
    #   both         — achievable by either class
    attacker_class_map: Dict[str, str] = field(default_factory=lambda: {
        "replay_token":            "non_invasive",
        "nonce_reuse":             "non_invasive",
        "timestamp_inconsistency": "non_invasive",
        "duplicate_sequence":      "non_invasive",
        "impersonation":           "non_invasive",
        "identity_token_mismatch": "non_invasive",
        "access_without_auth":     "non_invasive",
        "abnormal_failure_rate":   "both",
        "connect_flood":           "both",
        "delayed_connect":         "both",
        "abnormal_renewal":        "invasive",
    })


# ══════════════════════════════════════════════════════════════════════════════
# 7.  ML pipeline
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MLConfig:
    """Settings for the machine-learning evaluation stage."""

    test_size:        float = 0.2
    validation_size:  float = 0.1
    stratify:         bool  = True

    # Random Forest
    rf_n_estimators: int = 100
    rf_max_depth:    int = 20

    # Decision Tree
    dt_max_depth: int = 15

    # Features to drop before training (identifiers, not signals)
    drop_columns: List[str] = field(default_factory=lambda: [
        "device_id",
        "claimed_device_id",
        "source_ip",
        "gateway_id",
        "message_id",
        "payload_hash",
        "requested_topic",
    ])


# ══════════════════════════════════════════════════════════════════════════════
# 8.  Convenience: single object grouping all configs
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Config:
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    network:    NetworkConfig    = field(default_factory=NetworkConfig)
    device:     DeviceConfig     = field(default_factory=DeviceConfig)
    security:   SecurityConfig   = field(default_factory=SecurityConfig)
    mqtt:       MQTTConfig       = field(default_factory=MQTTConfig)
    attack:     AttackConfig     = field(default_factory=AttackConfig)
    ml:         MLConfig         = field(default_factory=MLConfig)


# ── Default singleton (import and use directly) ────────────────────────────────
cfg = Config()