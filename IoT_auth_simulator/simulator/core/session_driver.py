"""
simulator/core/session_driver.py
─────────────────────────────────
Phase C — wire the core/ domain entities into the generation path.

The event engine synthesises the labelled event/feature stream with carefully
tuned, leakage-aware distributions. Historically the domain components in
``core/`` (Device, Gateway, AuthServer, MQTTBroker) were never exercised while
a dataset was generated — they existed only as a reference model.

``SessionDriver`` closes that gap. When entity wiring is enabled
(``cfg.simulation.wire_entities``), the runner creates the shared cloud
entities plus one gateway per gateway id, and hands the event engine a
``SessionDriver`` per session. As each nominal event fires, the driver drives
the *real* protocol on the real objects:

    discovery            → Gateway.respond_to_discovery + terminate_tls
    pairing              → Device/Gateway ECDH exchange (secp256r1)
    enrollment           → AuthServer.enroll_device + Gateway ABAC policy
    challenge            → Gateway.register_nonce (single-use nonce cache)
    token issuance       → AuthServer.issue_token  (real token id/expiry/scope)
    session open         → MQTTBroker.connect (AS revalidates the token)
    access granted       → MQTTBroker.publish + Gateway.authorize_topic (ABAC)
    session close        → MQTTBroker.disconnect

Design contract
───────────────
The driver is deliberately **schema-neutral and distribution-preserving**: it
does NOT overwrite any leakage-sensitive feature value (rates, latencies,
trust score, topic_scope_violation, credential_status, …). Its only effect on
the emitted data is to source the **real** token id from the AuthServer for the
event that issues it, so the event stream's ``token_id`` matches the token the
AuthServer actually minted. Everything else it does is side-effect only:
exercising the crypto/protocol and accumulating entity state (registry, nonce
cache, replay window, broker sessions) that the run summary reports.

Because the real ABAC/replay/keep-alive *decisions* are not fed back into the
feature columns, enabling wiring cannot re-introduce the label leakage the
synthesis path is tuned to avoid.
"""

from typing import Dict, Optional

from simulator.event_model import EventType


class SessionDriver:
    """
    Drives the real domain entities through one session's nominal events.

    Parameters
    ----------
    device      : the core.device.Device instance for this session
    gateway     : the core.gateway.Gateway handling this session
    auth_server : the shared core.auth_server.AuthServer
    broker      : the shared core.auth_server.MQTTBroker
    stats       : shared run-level counter dict (mutated in place) so the runner
                  can report aggregate entity activity across all sessions
    """

    def __init__(self, device, gateway, auth_server, broker, stats: Dict[str, int]):
        self.device      = device
        self.gateway     = gateway
        self.auth_server = auth_server
        self.broker      = broker
        self.stats       = stats

        self.device_id   = device.device_id
        self.source_ip   = device.ip_address
        self._psk_hash   = device.get_psk_hash()

        self._device_pub = None   # device ECDH public key, set during pairing
        self._token      = None   # last AccessToken issued this session

    # ──────────────────────────────────────────────────────────────────────────

    def on_event(self, event_type: EventType, rs: Dict, now: float) -> Optional[Dict]:
        """
        Drive the entities for one nominal event.

        Returns a dict of ``rs`` overrides to apply (only for TOKEN_ISSUED, which
        contributes the real token id), or ``None`` for pure side-effect events.
        """
        if event_type == EventType.DISCOVERY:
            self.gateway.respond_to_discovery(self.device_id, self.source_ip)
            self.gateway.terminate_tls(self.device_id, self.source_ip)
            self.stats["tls_channels"] += 1

        elif event_type == EventType.PAIRING_REQUEST:
            self._device_pub = self.device.generate_ecdh_keypair()

        elif event_type == EventType.PAIRING_RESPONSE:
            if self._device_pub is not None:
                gw_pub, _secret = self.gateway.perform_ecdh_exchange(
                    self.device_id, self._device_pub
                )
                self.device.compute_shared_secret(gw_pub)
                self.stats["ecdh_exchanges"] += 1

        elif event_type in (EventType.ENROLLMENT_CONFIRMED,
                            EventType.REGISTRATION_CONFIRMED):
            ok, _code = self.auth_server.enroll_device(self.device_id, self._psk_hash)
            if ok:
                self.stats["enrollments"] += 1
                # ABAC: grant the device its own topic sub-tree (Zero-Trust default
                # is deny, so a policy must be set for later authorize_topic checks).
                self.gateway.set_policy(
                    self.device_id, f"iot/{self.device_id[:8]}/#", "pub_sub"
                )

        elif event_type == EventType.CHALLENGE_SENT:
            nonce = rs.get("nonce")
            if nonce:
                self.gateway.register_nonce(nonce, now=now)
                self.stats["nonces_cached"] += 1

        elif event_type == EventType.TOKEN_ISSUED:
            token, _reason = self.auth_server.issue_token(self.device_id, self._psk_hash)
            if token is not None:
                self._token = token
                self.gateway.relay_token(self.device_id, token.to_string(), token.issued_at)
                self.stats["tokens_issued"] += 1
                # Source the real token id into the emitted event (token_expiry /
                # token_scope stay engine-computed to preserve the simulated clock
                # and the varied scope distribution).
                return {"token_id": token.token_id}

        elif event_type == EventType.SESSION_OPENED:
            if self._token is not None:
                ok, _code, _meta = self.broker.connect(
                    self.device_id, self._token.to_string(), self.auth_server
                )
                if ok:
                    self.stats["broker_connects"] += 1

        elif event_type == EventType.ACCESS_GRANTED:
            topic = rs.get("topic") or f"iot/{self.device_id[:8]}/telemetry"
            self.broker.publish(self.device_id, topic, b"telemetry", qos=1)
            self.gateway.authorize_topic(self.device_id, topic, "publish")
            self.stats["publishes"] += 1

        elif event_type in (EventType.SESSION_CLOSED, EventType.DISCONNECT):
            self.broker.disconnect(self.device_id)

        return None
