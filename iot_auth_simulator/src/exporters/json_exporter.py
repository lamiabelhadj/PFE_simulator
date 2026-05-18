"""JSON exporter for events."""

import json
import logging
from pathlib import Path
from typing import List

from ..models.event import Event
from .csv_exporter import CSVExporter

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export events to JSON format."""
    
    @staticmethod
    def export(events: List[Event], output_path: Path) -> None:
        """
        Export events to JSON file.
        
        Args:
            events: List of events to export
            output_path: Path to output JSON file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert events to dictionaries, preserving only dataset feature fields
        events_data = [
            {field: event.to_dict().get(field, "") for field in CSVExporter.FIELDNAMES}
            for event in events
        ]
        
        with open(output_path, "w") as f:
            json.dump(events_data, f, indent=2)
        
        logger.info(f"Exported {len(events)} events to {output_path}")
