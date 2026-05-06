"""
============================================
BLACK WALL — Monitor Controller
============================================
API endpoints for system monitoring and webhooks:
  GET  /monitor/status — Wazuh file monitor status
  POST /test-alert     — Inject a test critical alert
  POST /webhook        — Receive external Wazuh alerts
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter

from app.services.alert_pipeline import process_alert

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/monitor/status")
def monitor_status():
    """Check the Wazuh file monitor status."""
    from app.workers.wazuh_monitor import get_monitor_instance
    monitor = get_monitor_instance()
    if monitor is None:
        return {"status": "not_initialized", "message": "Le monitor n'a pas été démarré."}
    return monitor.get_status()


@router.post("/test-alert")
def test_critical_alert():
    """
    Inject a fake critical alert to test the full pipeline.
    Useful for verifying: AI analysis, email, and SQLite save.
    """
    fake_alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "level": 14,
            "description": "[TEST] sshd: Multiple authentication failures — brute force attack detected.",
            "id": "5712",
            "groups": ["syslog", "sshd", "authentication_failed", "brute_force"],
        },
        "agent": {"name": "test-agent", "id": "999", "ip": "127.0.0.1"},
        "data": {"srcip": "185.220.101.44"},
        "full_log": "Failed password for root from 185.220.101.44 port 22 ssh2 (TEST)",
    }

    result = process_alert(fake_alert)

    if result:
        return {
            "status": "success",
            "message": "Alerte de test traitée avec succès.",
            "alert": result,
        }
    return {
        "status": "skipped",
        "message": "Alerte ignorée (doublon ou niveau insuffisant).",
    }


from app.services.detection_service import analyze_alerts
from app.repositories.postgres_repository import postgres_repo

@router.post("/webhook")
def wazuh_webhook(payload: dict):
    """
    Receive a Wazuh alert JSON and run the full processing pipeline.
    """
    try:
        # 1. Always process and save to PostgreSQL (for main dashboard)
        analysis_results = analyze_alerts([payload])
        if analysis_results.get("all_detections"):
            postgres_repo.save_detections(analysis_results["all_detections"])

        # 2. Process for critical pipeline (AI, Email, SQLite) if level >= CRITICAL_ALERT_LEVEL
        result = process_alert(payload)
        
        return {"status": "accepted" if result else "saved_to_history", "alert": result}
    except Exception as e:
        logger.error("Webhook processing error: %s", e)
        return {"status": "error", "detail": str(e)}
