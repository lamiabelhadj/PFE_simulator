"""
simulator/engines/temporal_engine.py
──────────────────────────────────────
Phase 3 — Temporal Engine

Manages time-dependent session logic that the EventEngine delegates to:

  Token lifecycle
    - Records when a token is issued / renewed
    - Detects expiry and renewal threshold crossing
    - Computes token age at any moment

  Nonce lifecycle
    - Records challenge issue time
    - Detects nonce expiry (replay window for challenge-response)

  Retry policy
    - Tracks consecutive failure count
    - Computes exponential-backoff delay for RETRY events
    - Reports when max retries are exhausted

  Replay window
    - Checks whether a presented token is outside the allowed reuse window
    - Used to set replay_window_violation in SessionContext

One TemporalEngine instance is created per session by the EventEngine.
"""

import random
from dataclasses import dataclass
from typing import Optional


# ── Default lifetime constants (seconds) ──────────────────────────────────────
DEFAULT_TOKEN_LIFETIME     = 3600.0   # 1 hour
DEFAULT_ATTACK_TOKEN_LIFE  = 120.0    # 2 min — short, more exploitable
DEFAULT_NONCE_LIFETIME     = 30.0     # nonce expires after 30 s
DEFAULT_RENEWAL_THRESHOLD  = 0.80     # renew when 80 % of lifetime elapsed
DEFAULT_REPLAY_WINDOW      = 60.0     # token presented > 60 s after issuance = replay

DEFAULT_MAX_RETRIES   = 3
DEFAULT_BASE_BACKOFF  = 1.0           # seconds
DEFAULT_BACKOFF_FACTOR = 2.0          # exponential multiplier


@dataclass
class TemporalConfig:
    token_lifetime:      float = DEFAULT_TOKEN_LIFETIME
    attack_token_life:   float = DEFAULT_ATTACK_TOKEN_LIFE
    nonce_lifetime:      float = DEFAULT_NONCE_LIFETIME
    renewal_threshold:   float = DEFAULT_RENEWAL_THRESHOLD
    replay_window:       float = DEFAULT_REPLAY_WINDOW
    max_retries:         int   = DEFAULT_MAX_RETRIES
    base_backoff:        float = DEFAULT_BASE_BACKOFF
    backoff_factor:      float = DEFAULT_BACKOFF_FACTOR


class TemporalEngine:
    """
    Per-session temporal state tracker.

    Parameters
    ----------
    config    : TemporalConfig — lifetimes and retry policy
    is_attack : if True, uses the shorter attack token lifetime
    """

    def __init__(
        self,
        config:    Optional[TemporalConfig] = None,
        is_attack: bool = False,
    ):
        self.cfg       = config or TemporalConfig()
        self.is_attack = is_attack

        self._token_issued_at:    Optional[float] = None
        self._token_presented_at: Optional[float] = None
        self._nonce_issued_at:    Optional[float] = None
        self._retry_count:        int             = 0
        self._renewal_count:      int             = 0

        self._effective_token_life = (
            self.cfg.attack_token_life if is_attack
            else self.cfg.token_lifetime
        )

    # ── Token lifecycle ───────────────────────────────────────────────────────

    def record_token_issued(self, now: float) -> None:
        self._token_issued_at = now

    def record_token_presented(self, now: float) -> None:
        self._token_presented_at = now

    def is_token_expired(self, now: float) -> bool:
        if self._token_issued_at is None:
            return False
        return (now - self._token_issued_at) >= self._effective_token_life

    def should_renew(self, now: float) -> bool:
        """True when >= renewal_threshold of token lifetime has elapsed."""
        if self._token_issued_at is None:
            return False
        elapsed = now - self._token_issued_at
        return elapsed >= self._effective_token_life * self.cfg.renewal_threshold

    def token_age(self, now: float) -> float:
        if self._token_issued_at is None:
            return 0.0
        return max(0.0, now - self._token_issued_at)

    def time_until_expiry(self, now: float) -> float:
        if self._token_issued_at is None:
            return self._effective_token_life
        return max(0.0, self._effective_token_life - (now - self._token_issued_at))

    def record_renewal(self, now: float) -> None:
        """Reset token lifetime clock on successful renewal."""
        self._token_issued_at = now
        self._renewal_count  += 1

    @property
    def renewal_count(self) -> int:
        return self._renewal_count

    # ── Nonce lifecycle ───────────────────────────────────────────────────────

    def record_nonce_issued(self, now: float) -> None:
        self._nonce_issued_at = now

    def is_nonce_expired(self, now: float) -> bool:
        if self._nonce_issued_at is None:
            return False
        return (now - self._nonce_issued_at) >= self.cfg.nonce_lifetime

    def nonce_age(self, now: float) -> float:
        if self._nonce_issued_at is None:
            return 0.0
        return max(0.0, now - self._nonce_issued_at)

    # ── Replay window ─────────────────────────────────────────────────────────

    def is_replay_violation(self, now: float) -> bool:
        """
        True if the token is presented outside the allowed replay window.

        Condition: token_presented_at - token_issued_at > replay_window,
        meaning the attacker waited longer than the allowed window before
        replaying the token.
        """
        if self._token_issued_at is None or self._token_presented_at is None:
            return False
        age = self._token_presented_at - self._token_issued_at
        return age > self.cfg.replay_window

    # ── Retry policy ──────────────────────────────────────────────────────────

    def record_failure(self) -> None:
        self._retry_count += 1

    def can_retry(self) -> bool:
        return self._retry_count < self.cfg.max_retries

    def next_retry_delay(self) -> float:
        """Exponential backoff with ±20 % uniform jitter."""
        base   = self.cfg.base_backoff * (self.cfg.backoff_factor ** self._retry_count)
        jitter = random.uniform(-base * 0.2, base * 0.2)
        return round(max(0.05, base + jitter), 3)

    def exhausted(self) -> bool:
        return self._retry_count >= self.cfg.max_retries

    @property
    def retry_count(self) -> int:
        return self._retry_count
