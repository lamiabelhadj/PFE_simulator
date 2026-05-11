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
        # Identity and Discovery Features
        "device_id",
        "claimed_device_id",
        "source_ip",
        "gateway_id",
        "registered_device",
        "source_connection_count",
        "source_diversity",
        # Pairing and Network Features
        "tcp_flags",
        "connection_duration",
        "tcp_rtt",
        "packet_rate",
        "inter_arrival_time",
        "frame_length",
        "tcp_segment_len",
        "pairing_result",
        "pairing_latency_ms",
        # Enrollment and Authentication Features
        "credential_status",
        "mqtt_msg_type",
        "connect_flags",
        "clean_session",
        "username_present",
        "password_present",
        "username_length",
        "password_length",
        "keep_alive",
        "mqtt_version",
        "connack_code",
        "auth_result",
        "auth_latency_ms",
        "failed_auth_count",
        # Authorization Features
        "requested_topic",
        "topic_length",
        "operation",
        "requested_qos",
        "granted_qos",
        "authorization_result",
        "topic_scope_violation",
        "retain_flag",
        # MQTT Session Features
        "message_id",
        "duplicate_flag",
        "payload_length",
        "payload_hash",
        "hash_method",
        "qos_level",
        "message_rate",
        "byte_rate",
        "session_duration",
        # Continuous Re-authentication Features
        "trust_score",
        "re_auth_required",
        "gateway_decision",
        "session_present",
        "source_ip_change",
        "replay_window_violation",
        "behavior_deviation_score",
        # Labels
        "lifecycle_phase",
        "is_anomaly",
        "attack_type",
        "attack_phase",
        "severity",
        "attacker_type",
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
