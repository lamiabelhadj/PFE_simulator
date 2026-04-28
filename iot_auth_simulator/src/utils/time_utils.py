"""Time utility functions."""

from datetime import datetime


class TimeUtils:
    """Utilities for time-related operations."""
    
    @staticmethod
    def now_iso() -> str:
        """Get current time in ISO format."""
        return datetime.utcnow().isoformat()
    
    @staticmethod
    def timestamp_to_iso(ts: datetime) -> str:
        """Convert datetime to ISO format string."""
        return ts.isoformat()
