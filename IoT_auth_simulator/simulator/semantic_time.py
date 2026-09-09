"""Authoritative semantic time for sequential generated traces.

The clock measures seconds in a synthetic timeline.  Its initial coordinate may
be anchored to a caller-supplied Unix timestamp for readable exports, but only
this clock and its advances determine generated semantic ordering and validity.
Execution wall time is not consulted after construction.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


SEMANTIC_TIME_DOMAIN = "synthetic-sequential-seconds"
SEMANTIC_TIMESTAMP_FIELD = "timestamp"
OBSERVED_TIMESTAMP_FIELD = "observed_timestamp"
MINIMUM_CAUSAL_INCREMENT_S = 0.000001


@dataclass
class SemanticClock:
    """Monotonic clock owned by one generated trace execution."""

    current_time: float

    def __post_init__(self) -> None:
        self.current_time = float(self.current_time)
        if not math.isfinite(self.current_time):
            raise ValueError("semantic time origin must be finite")

    @property
    def now(self) -> float:
        return self.current_time

    def advance(self, delay_s: float) -> float:
        """Advance one causal step, guaranteeing strict sequential ordering."""
        delay_s = float(delay_s)
        if not math.isfinite(delay_s) or delay_s < 0:
            raise ValueError("semantic delay must be finite and non-negative")
        self.current_time += max(delay_s, MINIMUM_CAUSAL_INCREMENT_S)
        return self.current_time


def temporal_contract_metadata(config: Any) -> dict[str, Any]:
    """Machine-readable C1.4 classification of active temporal parameters.

    The statuses describe implementation use; they do not make the parameters
    canonical Behavioral-model-v1 values.
    """
    return {
        "semantic_time_domain": SEMANTIC_TIME_DOMAIN,
        "semantic_timestamp_field": SEMANTIC_TIMESTAMP_FIELD,
        "observed_timestamp_field": OBSERVED_TIMESTAMP_FIELD,
        "execution_wall_clock_role": "run/execution metadata or timeline anchor only",
        "rules": {
            "causal_event_ordering": "currently enforced semantic rule",
            "configured_token_expiry": "currently enforced semantic rule",
            "challenge_nonce_freshness": "annotation only",
            "protected_session_chronology": "currently enforced semantic rule",
            "renewal_threshold": "unused/dead",
            "token_replay_window": "unresolved semantic dependency",
        },
        "parameters": {
            "security.token_lifetime_s": {
                "value": config.security.token_lifetime_s,
                "status": "currently enforced semantic rule",
                "authority": "historical reference-profile configuration",
            },
            "security.token_lifetime_short_s": {
                "value": config.security.token_lifetime_short_s,
                "status": "implementation/reference-profile parameter",
                "enforcement": "not used by the default generated semantic path",
            },
            "temporal.nonce_lifetime_s": {
                "value": 30.0,
                "status": "annotation only",
                "enforcement": "helper exists; default generated validity does not use it",
            },
            "security.replay_window_s": {
                "value": config.security.replay_window_s,
                "status": "unresolved semantic dependency",
                "enforcement": "optional wired cache only; not canonical anomaly truth",
            },
            "legacy_temporal_engine_replay_window_s": {
                "value": 60.0,
                "status": "inconsistent/conflicting",
                "enforcement": "overridden in the synchronized EventEngine; not canonical",
            },
            "attack.configured_replay_token_age_range_s": {
                "value": [
                    config.attack.replay_token_age_min_s,
                    config.attack.replay_token_age_max_s,
                ],
                "status": "unused/dead",
                "enforcement": "not consumed by the historical injection path",
            },
            "attack.hard_coded_replay_age_range_s": {
                "value": [120.0, 600.0],
                "status": "annotation only",
                "enforcement": "historical injection parameter; not replay semantics",
            },
            "attack.hard_coded_timestamp_offset_range_s": {
                "value": [400.0, 900.0],
                "status": "annotation only",
                "enforcement": "historical injection parameter; not temporal semantics",
            },
            "temporal.renewal_threshold_fraction": {
                "value": 0.80,
                "status": "unused/dead",
                "enforcement": "not used to validate generated renewal requests",
            },
            "legacy_temporal_engine_token_lifetime_s": {
                "value": 3600.0,
                "status": "inconsistent/conflicting",
                "enforcement": "not active in the synchronized EventEngine path",
            },
            "legacy_temporal_engine_attack_token_lifetime_s": {
                "value": 120.0,
                "status": "inconsistent/conflicting",
                "enforcement": "not active in the synchronized EventEngine path",
            },
        },
    }
