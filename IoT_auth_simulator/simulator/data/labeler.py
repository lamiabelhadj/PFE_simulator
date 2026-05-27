"""
data/labeler.py
────────────────
Adds labels to normal (benign) session events.
Attack sessions are already labelled by their attack module.
"""

from typing import Dict, Any


def label_normal(event: Dict[str, Any]) -> Dict[str, Any]:
    """Stamp a benign session with its ground-truth labels."""
    event["is_anomaly"]   = 0
    event["attack_type"]  = "normal"
    event["attack_phase"] = "none"
    event["severity"]     = "none"
    return event


def label_attack(event: Dict[str, Any], attack_type: str, phase: str, severity: str) -> Dict[str, Any]:
    """Override labels on an attack event (used when attack modules don't set them)."""
    event["is_anomaly"]   = 1
    event["attack_type"]  = attack_type
    event["attack_phase"] = phase
    event["severity"]     = severity
    return event