"""
simulator/core/gateway.py
─────────────────────────
Represents the Edge Gateway — the single trusted enforcement point between
IoT devices and the cloud (AuthServer + MQTT Broker).

"""

import time
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.backends import default_backend

from simulator.config.settings import cfg


# ── Per-device session record held by the gateway ─────────────────────────────

@dataclass
class DeviceSession:
    device_id:       str
    source_ip:       str
    shared_secret:   Optional[bytes] = None
    token:           Optional[str]   = None
    token_issued_at: Optional[float] = None
    last_seen:       float           = field(default_factory=time.time)
    active:          bool            = True

    # Connection-level counters
    connection_count: int = 0
    failed_count:     int = 0

    # Seen source IPs for this device (diversity tracking)
    seen_ips: Set[str] = field(default_factory=set)

    def register_ip(self, ip: str) -> None:
        self.seen_ips.add(ip)

    @property
    def source_diversity(self) -> int:
        return len(self.seen_ips)

    @property
    def ip_changed(self) -> bool:
        """True if the device connected from more than one IP."""
        return self.source_diversity > 1


# ── Gateway ────────────────────────────────────────────────────────────────────

@dataclass
class Gateway:
    """
    Edge gateway — the single trusted enforcement point.

    All security decisions for devices in this simulation pass through here.
    Its responsibilities mirror the functional model:
      (i)   terminate the device-facing TLS channel and re-establish one to cloud
      (ii)  validate tokens against the authorization server
      (iii) enforce ABAC policy on publish/subscribe requests
      (iv)  rate-limit devices that fail authentication repeatedly
      (v)   detect protocol-level anomalies (duplicate nonces, replayed tokens)
            within its bounded memory window
    """

    gateway_id: str
    ip_address: str = field(default_factory=lambda: cfg.network.gateway_ip)

    # ── TLS: the gateway terminates the device-facing TLS channel and
    #    re-establishes a separate one toward the cloud. ────────────────────────
    tls_enabled: bool = True
    tls_version: str  = "TLSv1.3"

    # ── ECDH keypair (one per gateway, rotated conceptually per session) ───────
    _ecdh_private_key: object = field(default=None, repr=False)
    _ecdh_public_key:  object = field(default=None, repr=False)

    # ── Active device sessions keyed by device_id ─────────────────────────────
    sessions: Dict[str, DeviceSession] = field(default_factory=dict)

    # ── Replay-attack window: stores recently seen token hashes + timestamp ───
    _replay_window: Dict[str, float] = field(default_factory=dict)

    # ── Nonce cache for PoP-challenge replay detection (nonce → first-seen ts) ─
    _nonce_cache: Dict[str, float] = field(default_factory=dict)

    # ── ABAC policy table: device_id → list of allowed (topic_pattern, op) ─────
    #    Attribute-based access control on publish/subscribe requests.
    _policy_table: Dict[str, List[Tuple[str, str]]] = field(default_factory=dict)

    # ── Rate-limiting: request timestamps per source IP ───────────────────────
    _request_log: Dict[str, List[float]] = field(default_factory=lambda: defaultdict(list))

    # ── Event log (raw, consumed by feature_builder) ──────────────────────────
    event_log: List[dict] = field(default_factory=list)

    # ══════════════════════════════════════════════════════════════════════════
    # Lifecycle
    # ══════════════════════════════════════════════════════════════════════════

    def __post_init__(self) -> None:
        self._rotate_ecdh_keypair()

    def _rotate_ecdh_keypair(self) -> None:
        """Generate a fresh ECDH keypair for the gateway."""
        self._ecdh_private_key = generate_private_key(SECP256R1(), default_backend())
        self._ecdh_public_key  = self._ecdh_private_key.public_key()

    @property
    def public_key(self) -> EllipticCurvePublicKey:
        return self._ecdh_public_key

    # ══════════════════════════════════════════════════════════════════════════
    # TLS termination
    # ══════════════════════════════════════════════════════════════════════════

    def terminate_tls(self, device_id: str, source_ip: str) -> dict:
        """
        Terminate the device-facing TLS channel and re-establish a separate one
        toward the cloud. The gateway is the only component that spans both the
        constrained side and the cloud side, so it is where TLS is bridged.

        Returns a small channel descriptor (no real handshake is performed).
        """
        return {
            "tls_enabled":    self.tls_enabled,
            "device_channel": self.tls_version if self.tls_enabled else None,
            "cloud_channel":  self.tls_version if self.tls_enabled else None,
            "device_id":      device_id,
            "source_ip":      source_ip,
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Step 1 — Discovery
    # ══════════════════════════════════════════════════════════════════════════

    def respond_to_discovery(self, device_id: str, source_ip: str) -> dict:
        """
        Acknowledge a device discovery probe.
        Returns a service advertisement payload.
        """
        self._log_request(source_ip)
        session = self._get_or_create_session(device_id, source_ip)
        session.connection_count += 1

        return {
            "gateway_id":    self.gateway_id,
            "gateway_ip":    self.ip_address,
            "auth_endpoint": f"https://{cfg.network.auth_server_ip}/enroll",
            "broker_ip":     cfg.network.broker_ip,
            "services":      ["enrollment", "mqtt", "reauth"],
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Step 2 — Pairing (ECDH)
    # ══════════════════════════════════════════════════════════════════════════

    def perform_ecdh_exchange(
        self,
        device_id:         str,
        device_public_key: EllipticCurvePublicKey,
    ) -> Tuple[EllipticCurvePublicKey, bytes]:
        """
        Complete the ECDH handshake with the device.

        Returns
        -------
        (gateway_public_key, shared_secret)
        """
        shared_secret = self._ecdh_private_key.exchange(ECDH(), device_public_key)

        session = self.sessions.get(device_id)
        if session:
            session.shared_secret = shared_secret

        return self._ecdh_public_key, shared_secret

    # ══════════════════════════════════════════════════════════════════════════
    # Step 3 — Enrollment forwarding & access control
    # ══════════════════════════════════════════════════════════════════════════

    def allow_enrollment(self, device_id: str, source_ip: str) -> Tuple[bool, str]:
        """
        Gate-keep the enrollment request.

        Returns (allowed: bool, reason: str).
        Blocks devices that exceed the failed-auth threshold.
        """
        session = self.sessions.get(device_id)
        if session and session.failed_count >= cfg.security.max_failed_auth:
            return False, "max_failed_auth_exceeded"

        if self._is_rate_limited(source_ip):
            return False, "rate_limited"

        return True, "ok"

    # ══════════════════════════════════════════════════════════════════════════
    # Step 4 — Authorization token relay
    # ══════════════════════════════════════════════════════════════════════════

    def relay_token(self, device_id: str, token: str, issued_at: float) -> None:
        """Store the issued token in the device session for later validation."""
        session = self.sessions.get(device_id)
        if session:
            session.token           = token
            session.token_issued_at = issued_at

    # ══════════════════════════════════════════════════════════════════════════
    # Step 5 — MQTT session gating
    # ══════════════════════════════════════════════════════════════════════════

    def validate_mqtt_token(self, device_id: str, token: str) -> Tuple[bool, str]:
        """
        Verify the token before the broker allows Publish/Subscribe.

        Checks:
          1. Token matches what was issued
          2. Token has not expired
          3. Token hash not in replay window
        """
        session = self.sessions.get(device_id)
        if not session or session.token != token:
            return False, "token_mismatch"

        age = time.time() - (session.token_issued_at or 0)
        if age > cfg.security.token_lifetime_s:
            return False, "token_expired"

        if self._is_replay(token):
            return False, "replay_detected"

        self._register_in_replay_window(token)
        return True, "ok"

    # ══════════════════════════════════════════════════════════════════════════
    # Step 6 — Re-authentication / Zero-Trust continuous verification
    # ══════════════════════════════════════════════════════════════════════════

    def trigger_reauth(self, device_id: str, trust_score: float) -> Tuple[bool, str]:
        """
        Decide whether a re-authentication is required.

        Returns (reauth_required: bool, decision: str).
        """
        if trust_score < cfg.security.trust_score_threshold:
            return True, "trust_below_threshold"

        session = self.sessions.get(device_id)
        if session and session.ip_changed:
            return True, "ip_change_detected"

        return False, "session_valid"

    # ══════════════════════════════════════════════════════════════════════════
    # ABAC — attribute-based access control on publish/subscribe
    # ══════════════════════════════════════════════════════════════════════════

    def set_policy(self, device_id: str, topic_pattern: str, operation: str = "pub_sub") -> None:
        """
        Grant a device access to a topic pattern for a given operation.
        A trailing '#' in the pattern matches any sub-topic (MQTT-style).
        """
        self._policy_table.setdefault(device_id, []).append((topic_pattern, operation))

    def authorize_topic(self, device_id: str, topic: str, operation: str = "publish") -> Tuple[bool, str]:
        """
        Enforce ABAC on a publish/subscribe request.

        The decision uses the device_id, the requested topic, and the operation
        (attributes) against the gateway's policy table. Returns
        (allowed, reason). A device with no policy is denied by default
        (Zero-Trust: no implicit access).
        """
        rules = self._policy_table.get(device_id)
        if not rules:
            return False, "no_policy"

        for pattern, allowed_op in rules:
            if allowed_op not in (operation, "pub_sub"):
                continue
            if self._topic_matches(pattern, topic):
                return True, "authorized"
        return False, "topic_scope_violation"

    @staticmethod
    def _topic_matches(pattern: str, topic: str) -> bool:
        """MQTT-style match: a trailing '#' is a multi-level wildcard."""
        if pattern.endswith("#"):
            return topic.startswith(pattern[:-1])
        return pattern == topic

    # ══════════════════════════════════════════════════════════════════════════
    # PoP-challenge nonce cache (single-use nonce enforcement)
    # ══════════════════════════════════════════════════════════════════════════

    def is_nonce_replay(self, nonce: str, now: Optional[float] = None) -> bool:
        """
        True if this nonce is already present in the cache within its lifetime —
        i.e. a PoP challenge nonce is being reused. Expired entries are purged.
        """
        now = now if now is not None else time.time()
        # Purge entries older than the replay window before checking.
        self._nonce_cache = {
            n: ts for n, ts in self._nonce_cache.items()
            if now - ts <= cfg.security.replay_window_s
        }
        seen = self._nonce_cache.get(nonce)
        if seen is None:
            return False
        return (now - seen) <= cfg.security.replay_window_s

    def register_nonce(self, nonce: str, now: Optional[float] = None) -> None:
        """Record a freshly issued/consumed PoP nonce for replay detection."""
        self._nonce_cache[nonce] = now if now is not None else time.time()

    def record_session_failure(self, device_id: str) -> None:
        """Increment the failure counter for a device session."""
        session = self.sessions.get(device_id)
        if session:
            session.failed_count += 1

    def record_session_success(self, device_id: str) -> None:
        """Mark session as successfully re-authenticated."""
        session = self.sessions.get(device_id)
        if session:
            session.last_seen = time.time()

    # ══════════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _get_or_create_session(self, device_id: str, source_ip: str) -> DeviceSession:
        if device_id not in self.sessions:
            self.sessions[device_id] = DeviceSession(
                device_id=device_id,
                source_ip=source_ip,
            )
        session = self.sessions[device_id]
        session.register_ip(source_ip)
        return session

    def _is_rate_limited(self, source_ip: str, window_s: float = 5.0, max_req: int = 20) -> bool:
        """
        Simple sliding-window rate limiter per source IP.
        Returns True if the IP has exceeded max_req in the last window_s seconds.
        """
        now  = time.time()
        log  = self._request_log[source_ip]
        # Purge old entries
        self._request_log[source_ip] = [t for t in log if now - t < window_s]
        return len(self._request_log[source_ip]) >= max_req

    def _log_request(self, source_ip: str) -> None:
        self._request_log[source_ip].append(time.time())

    def _is_replay(self, token: str) -> bool:
        """Check whether this token was seen within the replay window."""
        token_hash = self._token_hash(token)
        if token_hash not in self._replay_window:
            return False
        age = time.time() - self._replay_window[token_hash]
        return age <= cfg.security.replay_window_s

    def _register_in_replay_window(self, token: str) -> None:
        self._replay_window[self._token_hash(token)] = time.time()

    @staticmethod
    def _token_hash(token: str) -> str:
        import hashlib
        return hashlib.blake2s(token.encode()).hexdigest()

    # ══════════════════════════════════════════════════════════════════════════
    # Observables
    # ══════════════════════════════════════════════════════════════════════════

    def get_session(self, device_id: str) -> Optional[DeviceSession]:
        return self.sessions.get(device_id)

    def log_event(self, event: dict) -> None:
        """Append a structured event dict to the gateway's event log."""
        self.event_log.append(event)

    def __repr__(self) -> str:
        return (
            f"Gateway(id={self.gateway_id}, ip={self.ip_address}, "
            f"sessions={len(self.sessions)})"
        )