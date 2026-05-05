"""
============================================
BLACK WALL — Wazuh Alert Monitor Worker
============================================
Daemon thread that watches the Wazuh alerts.json file (tail -f style).
Detects new log lines and file rotations, feeding each new entry
through the critical alert pipeline.
"""

import json
import logging
import os
import time
import threading
from datetime import datetime, timezone

from app.config import settings
from app.services.alert_pipeline import process_alert

logger = logging.getLogger(__name__)

# Module-level reference for the monitor singleton
_monitor_instance: "WazuhAlertMonitor | None" = None


class WazuhAlertMonitor:
    """
    Background file watcher that tails the Wazuh alerts log.
    Handles file rotation detection and recovers gracefully.
    """

    def __init__(self, log_path: str = settings.WAZUH_ALERTS_PATH, poll_interval: float = 2.0):
        self.log_path = log_path
        self.poll_interval = poll_interval
        self._thread: threading.Thread | None = None
        self._running = False

        # Stats
        self._file_position = 0
        self._alerts_processed = 0
        self._last_check: str | None = None
        self._errors: list[str] = []

    def start(self) -> None:
        """Start the monitor daemon thread."""
        if self._running:
            logger.warning("Monitor already running.")
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="WazuhMonitor")
        self._thread.start()
        logger.info("🔄 Wazuh monitor started — watching: %s", self.log_path)

    def stop(self) -> None:
        """Signal the monitor to stop."""
        self._running = False
        logger.info("Wazuh monitor stopping...")

    def get_status(self) -> dict:
        """Return current monitor status for the API."""
        return {
            "status": "running" if self._running else "stopped",
            "log_path": self.log_path,
            "file_position": self._file_position,
            "alerts_processed": self._alerts_processed,
            "last_check": self._last_check,
            "recent_errors": self._errors[-5:] if self._errors else [],
        }

    def _monitor_loop(self) -> None:
        """Main monitoring loop (runs in daemon thread)."""
        logger.info("Monitor thread started.")

        while self._running:
            try:
                self._last_check = datetime.now(timezone.utc).isoformat()

                if not os.path.exists(self.log_path):
                    time.sleep(self.poll_interval)
                    continue

                file_size = os.path.getsize(self.log_path)

                # Detect file rotation (file got smaller)
                if file_size < self._file_position:
                    logger.info("File rotation detected. Resetting position.")
                    self._file_position = 0

                if file_size == self._file_position:
                    time.sleep(self.poll_interval)
                    continue

                # Read new data
                with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(self._file_position)
                    new_data = f.read()
                    self._file_position = f.tell()

                # Process each new line
                for line in new_data.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        result = process_alert(alert)
                        if result:
                            self._alerts_processed += 1
                    except json.JSONDecodeError:
                        pass
                    except Exception as e:
                        error_msg = f"Alert processing error: {e}"
                        logger.error(error_msg)
                        self._errors.append(error_msg)

            except Exception as e:
                error_msg = f"Monitor loop error: {e}"
                logger.error(error_msg)
                self._errors.append(error_msg)

            time.sleep(self.poll_interval)

        logger.info("Monitor thread stopped.")


def get_monitor_instance() -> WazuhAlertMonitor | None:
    """Get the global monitor instance."""
    return _monitor_instance


def create_and_start_monitor() -> WazuhAlertMonitor:
    """Create, store, and start the global monitor instance."""
    global _monitor_instance
    _monitor_instance = WazuhAlertMonitor()
    _monitor_instance.start()
    return _monitor_instance
