"""
simulator/core/device.py
────────────────────────
Represents a     # ── Battery ──────────────────────────────────────────────────────────
    battery_level: int = field(
        default_factory=lambda: round(
            random.uniform(cfg.device.battery_min, cfg.device.battery_max), 1
        )
    ) IoT device in the simulation.

Responsibilities:
  - Holds identity (device_id, PSK, device_type, IP)
  - Tracks state across the 6 authentication flow steps
  - Exposes crypto helpers (ECDH key generation, Blake2s hashing)
  - Provides observable attributes consumed by feature_builder.py
"""

import hashlib
import os
import random
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.backends import default_backend

from config.settings import cfg


# ── Device lifecycle states ────────────────────────────────────────────────────

class DeviceState(Enum):
    IDLE          = auto()   # not yet started
    DISCOVERING   = auto()   # Step 1 — looking for gateway
    PAIRING       = auto()   # Step 2 — ECDH handshake
    ENROLLING     = auto()   # Step 3 — PSK enrollment
    AUTHORIZING   = auto()   # Step 4 — token request
    SESSION_OPEN  = auto()   # Step 5 — MQTT session active
    REAUTHENTCNG  = auto()   # Step 6 — token revalidation
    COMPLETED     = auto()   # clean session end
    FAILED        = auto()   # auth failure / anomaly detected
    ATTACKING     = auto()   # device is executing an attack


# ── Device identity & runtime state ───────────────────────────────────────────

@dataclass
class Device:
    """
    Simulates an IoT endpoint across all authentication steps.

    Parameters
    ----------
    device_id   : str  — canonical identifier (UUID-based)
    device_type : str  — sensor / actuator / camera / …
    ip_address  : str  — simulated source IP
    is_attacker : bool — whether this device is injecting an attack
    """

    device_id:   str
    device_type: str
    ip_address:  str
    is_attacker: bool = False

    # ── Credentials ──────────────────────────────────────────────────────────
    psk:              bytes         = field(default_factory=lambda: os.urandom(cfg.device.psk_length_bytes))
    credential_valid: bool          = True   # flipped by attack modules

    # ── Battery ──────────────────────────────────────────────────────────────
    battery_level: int = field(
        default_factory=lambda: round(
            random.uniform(cfg.device.battery_min, cfg.device.battery_max), 1
        )
    )

    # ── State machine ─────────────────────────────────────────────────────────
    state: DeviceState = field(default=DeviceState.IDLE)

    # ── ECDH keys (set during Pairing step) ───────────────────────────────────
    _ecdh_private_key: object = field(default=None, repr=False)
    _shared_secret:    bytes  = field(default=None, repr=False)

    # ── OAuth2 / ACE token (set during Authorization step) ────────────────────
    access_token:    Optional[str]   = field(default=None)
    token_issued_at: Optional[float] = field(default=None)   # Unix timestamp

    # ── Session tracking ──────────────────────────────────────────────────────
    failed_auth_count:        int   = 0
    source_connection_count:  int   = 0   # total connections this device made
    source_diversity:         int   = 1   # number of distinct source IPs seen

    # ── Trust ─────────────────────────────────────────────────────────────────
    trust_score: float = field(default_factory=lambda: cfg.security.trust_score_initial)

    # ══════════════════════════════════════════════════════════════════════════
    # Factory
    # ══════════════════════════════════════════════════════════════════════════

    @classmethod
    def create(
        cls,
        index:       int,
        is_attacker: bool = False,
        ip_override: Optional[str] = None,
    ) -> "Device":
        """
        Convenience factory used by the runner.

        Parameters
        ----------
        index       : position in device pool (used for deterministic IP)
        is_attacker : mark this device as malicious
        ip_override : force a specific IP (used in impersonation attacks)
        """
        device_id   = str(uuid.uuid4())
        device_type = random.choice(cfg.device.device_types)

        # Build source IP from subnet + index (wraps at 254)
        octet      = (index % 254) + 1
        ip_address = ip_override or f"{cfg.network.device_subnet}{octet}"

        device = cls(
            device_id=device_id,
            device_type=device_type,
            ip_address=ip_address,
            is_attacker=is_attacker,
        )

        if is_attacker:
            device.state = DeviceState.ATTACKING

        return device

    # ══════════════════════════════════════════════════════════════════════════
    # Cryptography helpers
    # ══════════════════════════════════════════════════════════════════════════

    def generate_ecdh_keypair(self) -> EllipticCurvePublicKey:
        """
        Generate an ECDH key pair on secp256r1.
        Returns the public key to send to the gateway.
        Called during Step 2 (Pairing).
        """
        self._ecdh_private_key = generate_private_key(
            SECP256R1(), default_backend()
        )
        return self._ecdh_private_key.public_key()

    def compute_shared_secret(self, peer_public_key: EllipticCurvePublicKey) -> bytes:
        """
        Derive the ECDH shared secret from the gateway's public key.
        Stores it internally and returns it.
        Called during Step 2 (Pairing).
        """
        if self._ecdh_private_key is None:
            raise RuntimeError("ECDH keypair not generated yet. Call generate_ecdh_keypair() first.")

        self._shared_secret = self._ecdh_private_key.exchange(
            ECDH(), peer_public_key
        )
        return self._shared_secret

    def blake2s_hash(self, data: bytes) -> str:
        """
        Compute a Blake2s digest of arbitrary data.
        Used to fingerprint payloads in MQTT session features.
        """
        return hashlib.blake2s(data).hexdigest()

    def get_psk_hash(self) -> str:
        """Return a Blake2s hash of the PSK (never expose raw PSK in dataset)."""
        return self.blake2s_hash(self.psk)

    # ══════════════════════════════════════════════════════════════════════════
    # State transitions
    # ══════════════════════════════════════════════════════════════════════════

    def transition(self, new_state: DeviceState) -> None:
        """Move the device to a new lifecycle state."""
        self.state = new_state

    def register_failed_auth(self) -> None:
        """Increment failed auth counter and degrade trust score."""
        self.failed_auth_count += 1
        self.trust_score = max(0.0, self.trust_score - 0.15)

    def register_successful_auth(self) -> None:
        """Slightly recover trust score on success."""
        self.trust_score = min(1.0, self.trust_score + 0.05)

    def needs_reauth(self) -> bool:
        """True if trust score fell below the Zero-Trust threshold."""
        return self.trust_score < cfg.security.trust_score_threshold

    # ══════════════════════════════════════════════════════════════════════════
    # Observables (consumed by feature_builder)
    # ══════════════════════════════════════════════════════════════════════════

    def to_identity_features(self) -> dict:
        """
        Keys map directly to the dataset column names.
        """
        return {
            "device_id":               self.device_id,
            "source_ip":               self.ip_address,
            "registered_device":       int(self.credential_valid),
            "source_connection_count": self.source_connection_count,
            "source_diversity":        self.source_diversity,
            "battery_level":           self.battery_level,
        }

    def __repr__(self) -> str:
        return (
            f"Device(id={self.device_id[:8]}…, type={self.device_type}, "
            f"ip={self.ip_address}, state={self.state.name}, "
            f"trust={self.trust_score:.2f}, attacker={self.is_attacker})"
        )