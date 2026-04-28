"""CSV exporter for events."""

import csv
import logging
from pathlib import Path
from typing import List

from ..models.event import Event

logger = logging.getLogger(__name__)


class CSVExporter:
    """Export events to CSV format."""
    
    # All fields that will be exported
    FIELDNAMES = [
        # Temporal
        "timestamp",
        # Device Identity
        "device_id",
        "device_type",
        "resource_class",
        "identity_method",
        "known_to_registry",
        # Authentication Lifecycle
        "lifecycle_phase",
        "auth_method",
        "auth_result",
        "auth_duration_ms",
        "tls_enabled",
        # Token Information
        "token_id",
        "token_valid",
        "token_expired",
        "token_scope",
        # Authorization & MQTT
        "requested_topic",
        "token_scope_match",
        "mqtt_version",
        "qos_level",
        "topic",
        "acl_match",
        # Message/Connection Metrics
        "message_frequency",
        "payload_size_bytes",
        "latency_ms",
        "connection_duration_s",
        "keep_alive_s",
        "clean_session_flag",
        "mqtt_conack_val",
        # Anomaly Indicators
        "duplicate_message_flag",
        "message_frequency_anomaly_flag",
        "latency_anomaly_flag",
        # Attack Information
        "attack_type",
        "attacker_type",
        "is_anomaly",
    ]
    
    @staticmethod
    def export(events: List[Event], output_path: Path) -> None:
        """
        Export events to CSV file.
        
        Args:
            events: List of events to export
            output_path: Path to output CSV file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSVExporter.FIELDNAMES)
            writer.writeheader()
            
            for event in events:
                row = event.to_dict()
                # Ensure all fields exist
                for field in CSVExporter.FIELDNAMES:
                    if field not in row:
                        row[field] = ""
                writer.writerow({field: row.get(field, "") for field in CSVExporter.FIELDNAMES})
        
        logger.info(f"Exported {len(events)} events to {output_path}")
