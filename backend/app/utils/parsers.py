"""
============================================
BLACK WALL — Log Parsers & Helpers
============================================
Utility functions for parsing Wazuh JSON logs
and handling timestamp conversions.
"""

import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def load_wazuh_logs(filepath: str) -> list[dict]:
    """
    Load Wazuh alerts from a JSON file.
    Supports both JSON array format and NDJSON (one JSON object per line).
    """
    alerts: list[dict] = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except FileNotFoundError:
        logger.warning("Wazuh log file not found: %s", filepath)
        return []
    except OSError as e:
        logger.error("Error reading Wazuh log file %s: %s", filepath, e)
        return []

    if not content:
        return []

    # Try parsing as a single JSON document first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON (one JSON object per line)
    for line in content.splitlines():
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return alerts


def parse_timestamp(ts_str: str | None) -> datetime:
    """
    Parse a timestamp string into a datetime object.
    Handles Wazuh's standard ISO format with timezone offsets.
    Falls back to current UTC time on failure.
    """
    if ts_str is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace("+0000", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)
