"""
simulator/core/auth_server.py
──────────────────────────────
Cloud-side components:
  • AuthServer  — PSK enrollment, OAuth2/ACE token issuance
  • MQTTBroker  — session management, Publish/Subscribe gating

Both live in the same module because in the simulation they share state
(device registry, issued tokens) and are colocated in the Cloud layer.

"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from simulator.config.settings import cfg


# ══════════════════════════════════════════════════════════════════════════════
# Token record
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AccessToken:
    """Represents an OAuth2/ACE access token."""

    token_id:   str
    device_id:  str
    issued_at:  float
    expires_at: float
    scope:      str       # e.g. "mqtt:pub mqtt:sub"

    @property
    def is_expired(self) -> bool:
        """Wall-clock convenience for standalone/debug use."""
        return self.is_expired_at(time.time())

    def is_expired_at(self, now: float) -> bool:
        """Evaluate expiry in the caller's declared time domain."""
        return float(now) >= self.expires_at

    @property
    def lifetime_s(self) -> float:
        return self.expires_at - self.issued_at

    def to_string(self) -> str:
        """Compact string representation passed between components."""
        return f"{self.token_id}:{self.device_id}:{int(self.issued_at)}"


# ══════════════════════════════════════════════════════════════════════════════
# AuthServer
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthServer:
    """
    Cloud authentication server.

    Handles:
      - Step 3 : PSK-based enrollment (verify & register device identity)
      - Step 4 : OAuth2/ACE token issuance
      - Step 6 : Token revalidation for continuous Zero-Trust verification
      - Revocation : revoke tokens on demand (decommission / anomaly response)
    """

    server_id:  str
    ip_address: str = field(default_factory=lambda: cfg.network.auth_server_ip)

    # ── Device registry: device_id → psk_hash ────────────────────────────────
    _registry: Dict[str, str] = field(default_factory=dict)

    # ── Issued tokens: token_id → AccessToken ────────────────────────────────
    _tokens: Dict[str, AccessToken] = field(default_factory=dict)

    # ── Revocation list: token_id → reason ───────────────────────────────────
    _revoked: Dict[str, str] = field(default_factory=dict)

    # ── Metrics ───────────────────────────────────────────────────────────────
    total_enrollments:    int = 0
    total_tokens_issued:  int = 0
    total_token_failures: int = 0
    total_revocations:    int = 0

    # ══════════════════════════════════════════════════════════════════════════
    # Step 3 — Enrollment
    # ══════════════════════════════════════════════════════════════════════════

    def enroll_device(
        self,
        device_id:        str,
        psk_hash:         str,
        credential_valid: bool = True,
    ) -> Tuple[bool, str]:
        """
        Verify and register a device's identity.

        Parameters
        ----------
        device_id        : claimed device identifier
        psk_hash         : Blake2s hash of the device's PSK
        credential_valid : False when an attacker sends a forged/stolen PSK

        Returns
        -------
        (success: bool, connack_code: str)
          connack_code mirrors MQTT CONNACK reason codes for realism.
        """
        if not credential_valid:
            self.total_token_failures += 1
            return False, "bad_user_name_or_password"

        if not psk_hash or len(psk_hash) < 8:
            return False, "malformed_credentials"

        # Register
        self._registry[device_id] = psk_hash
        self.total_enrollments += 1
        return True, "success"

    def is_registered(self, device_id: str) -> bool:
        return device_id in self._registry

    # ══════════════════════════════════════════════════════════════════════════
    # Step 4 — Token issuance (OAuth2 / ACE)
    # ══════════════════════════════════════════════════════════════════════════

    def issue_token(
        self,
        device_id:      str,
        psk_hash:       str,
        short_lifetime: bool = False,
        now: Optional[float] = None,
    ) -> Tuple[Optional[AccessToken], str]:
        """
        Issue an OAuth2/ACE access token.

        Parameters
        ----------
        device_id      : registered device requesting the token
        psk_hash       : must match the registry entry
        short_lifetime : True for re-auth / attack scenarios

        Returns
        -------
        (token: AccessToken | None, reason: str)
        """
        if not self.is_registered(device_id):
            self.total_token_failures += 1
            return None, "device_not_registered"

        if self._registry.get(device_id) != psk_hash:
            self.total_token_failures += 1
            return None, "psk_mismatch"

        now      = float(now) if now is not None else time.time()
        lifetime = (
            cfg.security.token_lifetime_short_s
            if short_lifetime
            else cfg.security.token_lifetime_s
        )
        token_id = str(uuid.uuid4())

        token = AccessToken(
            token_id   = token_id,
            device_id  = device_id,
            issued_at  = now,
            expires_at = now + lifetime,
            scope      = "mqtt:pub mqtt:sub",
        )

        self._tokens[token_id] = token
        self.total_tokens_issued += 1
        return token, "token_issued"

    # ══════════════════════════════════════════════════════════════════════════
    # Token revocation (decommission / anomaly response)
    # ══════════════════════════════════════════════════════════════════════════

    def revoke_token(self, token_id: str, reason: str = "revoked") -> bool:
        """
        Revoke an issued token on demand.

        Called either because a device has been decommissioned or because the
        gateway flagged its behaviour as anomalous. A revoked token fails every
        subsequent revalidation regardless of its expiry.

        Returns True if the token existed and was revoked, False otherwise.
        """
        if token_id not in self._tokens:
            return False
        self._revoked[token_id] = reason
        self.total_revocations += 1
        return True

    def is_revoked(self, token_id: str) -> bool:
        return token_id in self._revoked

    @property
    def revocation_list(self) -> Dict[str, str]:
        """Current revocation list (token_id → reason)."""
        return dict(self._revoked)

    # ══════════════════════════════════════════════════════════════════════════
    # Step 6 — Token revalidation
    # ══════════════════════════════════════════════════════════════════════════

    def revalidate_token(
        self,
        token_string: str,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Re-verify a token during continuous Zero-Trust revalidation.

        Parameters
        ----------
        token_string : compact token string from AccessToken.to_string()

        Returns
        -------
        (valid: bool, reason: str)
        """
        try:
            token_id, device_id, _ = token_string.split(":")
        except ValueError:
            return False, "malformed_token"

        if token_id in self._revoked:
            return False, "token_revoked"

        token = self._tokens.get(token_id)
        if not token:
            return False, "token_not_found"

        validation_time = float(now) if now is not None else time.time()
        if token.is_expired_at(validation_time):
            return False, "token_expired"

        return True, "revalidated"

    # ══════════════════════════════════════════════════════════════════════════
    # Observables
    # ══════════════════════════════════════════════════════════════════════════

    def get_token(self, token_id: str) -> Optional[AccessToken]:
        return self._tokens.get(token_id)

    def __repr__(self) -> str:
        return (
            f"AuthServer(id={self.server_id}, registered={len(self._registry)}, "
            f"tokens_issued={self.total_tokens_issued})"
        )


# ══════════════════════════════════════════════════════════════════════════════
# MQTT Broker
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MQTTBroker:
    """
    Simulates the MQTT v5 Broker in the Cloud layer.

    Responsibilities:
      - Step 5 : validate token, open session, gate Pub/Sub operations
      - Deliver messages at the requested QoS, holding QoS 1/2 messages in
        pending delivery queues until acknowledged
      - Track keep-alive to detect and close stale sessions
      - Tracks per-session metrics consumed by feature_builder
    """

    broker_id:  str
    ip_address: str = field(default_factory=lambda: cfg.network.broker_ip)

    # Active sessions: device_id → session metadata
    _sessions: Dict[str, dict] = field(default_factory=dict)

    # Counters
    total_connects:    int = 0
    total_disconnects: int = 0
    total_publishes:   int = 0
    total_subscribes:  int = 0

    # ══════════════════════════════════════════════════════════════════════════
    # Step 5 — MQTT CONNECT
    # ══════════════════════════════════════════════════════════════════════════

    def connect(
        self,
        device_id:     str,
        token_string:  str,
        auth_server:   AuthServer,
        clean_session: bool = True,
        keep_alive_s:  int  = None,
        now: Optional[float] = None,
    ) -> Tuple[bool, str, dict]:
        """
        Process an MQTT CONNECT from a device.

        Validates the token via the AuthServer, then opens a session.

        Returns
        -------
        (success: bool, connack_code: str, session_meta: dict)
        """
        keep_alive_s = keep_alive_s or cfg.device.keep_alive_normal_s

        semantic_now = float(now) if now is not None else time.time()
        valid, reason = auth_server.revalidate_token(token_string, now=semantic_now)
        if not valid:
            self.total_connects += 1
            return False, reason, {}

        session_present = device_id in self._sessions

        session_meta = {
            "session_present":  session_present,
            "clean_session":    clean_session,
            "keep_alive_s":     keep_alive_s,
            "connected_at":     semantic_now,
            "last_seen":        semantic_now,
            "publish_count":    0,
            "subscribe_count":  0,
            "byte_count":       0,
            "pending_qos1":     [],   # QoS 1 messages awaiting PUBACK
            "pending_qos2":     [],   # QoS 2 messages awaiting PUBCOMP
        }
        self._sessions[device_id] = session_meta
        self.total_connects += 1
        return True, "success", session_meta

    # ══════════════════════════════════════════════════════════════════════════
    # Step 5 — Publish / Subscribe
    # ══════════════════════════════════════════════════════════════════════════

    def publish(
        self,
        device_id: str,
        topic:     str,
        payload:   bytes,
        qos:       int  = 1,
        retain:    bool = False,
        now:       Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Simulate a PUBLISH operation, enforcing topic scope.

        QoS 1 and QoS 2 messages are appended to the session's pending delivery
        queue until acknowledged (see `acknowledge`); QoS 0 is fire-and-forget.
        """
        if device_id not in self._sessions:
            return False, "not_connected"

        topic_violation = not topic.startswith(cfg.mqtt.topic_prefix)

        session = self._sessions[device_id]
        session["publish_count"] += 1
        session["byte_count"]    += len(payload)
        session["last_seen"]      = float(now) if now is not None else time.time()
        self.total_publishes     += 1

        if topic_violation:
            return False, "topic_scope_violation"

        # Queue at-least-once / exactly-once messages until acknowledged.
        if qos == 1:
            session["pending_qos1"].append((topic, len(payload)))
        elif qos == 2:
            session["pending_qos2"].append((topic, len(payload)))

        return True, "published"

    def acknowledge(self, device_id: str, qos: int) -> bool:
        """Pop one pending QoS 1/2 message off the delivery queue (PUBACK/PUBCOMP)."""
        session = self._sessions.get(device_id)
        if not session:
            return False
        queue = session["pending_qos1"] if qos == 1 else session.get("pending_qos2", [])
        if queue:
            queue.pop(0)
            return True
        return False

    def subscribe(
        self,
        device_id: str,
        topic:     str,
        qos:       int = 1,
        now:       Optional[float] = None,
    ) -> Tuple[bool, int, str]:
        """
        Simulate a SUBSCRIBE operation.

        Returns (success, granted_qos, reason).
        """
        if device_id not in self._sessions:
            return False, 0, "not_connected"

        session = self._sessions[device_id]
        session["subscribe_count"] += 1
        session["last_seen"]        = float(now) if now is not None else time.time()
        self.total_subscribes      += 1

        granted_qos = min(qos, max(cfg.mqtt.qos_levels))
        return True, granted_qos, "granted"

    # ══════════════════════════════════════════════════════════════════════════
    # Keep-alive / stale-session detection
    # ══════════════════════════════════════════════════════════════════════════

    def stale_sessions(self, now: Optional[float] = None) -> Dict[str, dict]:
        """
        Return sessions that have exceeded 1.5x their keep-alive window without
        activity (MQTT treats these as stale and closes them).
        """
        now = now if now is not None else time.time()
        stale = {}
        for device_id, session in self._sessions.items():
            grace = session.get("keep_alive_s", cfg.device.keep_alive_normal_s) * 1.5
            if now - session.get("last_seen", now) > grace:
                stale[device_id] = session
        return stale

    def close_stale_sessions(self, now: Optional[float] = None) -> int:
        """Close every stale session and return how many were closed."""
        stale = self.stale_sessions(now)
        for device_id in stale:
            self.disconnect(device_id, now=now)
        return len(stale)

    # ══════════════════════════════════════════════════════════════════════════
    # Disconnect
    # ══════════════════════════════════════════════════════════════════════════

    def disconnect(self, device_id: str, now: Optional[float] = None) -> float:
        """Close the MQTT session and return session duration in seconds."""
        session = self._sessions.pop(device_id, None)
        if session:
            self.total_disconnects += 1
            semantic_now = float(now) if now is not None else time.time()
            return semantic_now - session.get("connected_at", semantic_now)
        return 0.0

    # ══════════════════════════════════════════════════════════════════════════
    # Observables
    # ══════════════════════════════════════════════════════════════════════════

    def get_session(self, device_id: str) -> Optional[dict]:
        return self._sessions.get(device_id)

    def session_duration(self, device_id: str, now: Optional[float] = None) -> float:
        session = self._sessions.get(device_id)
        if not session:
            return 0.0
        semantic_now = float(now) if now is not None else time.time()
        return semantic_now - session.get("connected_at", semantic_now)

    def __repr__(self) -> str:
        return (
            f"MQTTBroker(id={self.broker_id}, active_sessions={len(self._sessions)}, "
            f"publishes={self.total_publishes})"
        )
