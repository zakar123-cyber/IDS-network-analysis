"""
============================================
BLACK WALL — Alert Pipeline (Orchestrator)
============================================
Central pipeline for processing critical Wazuh alerts.

Steps: parse → dedup → AI analysis → save → email notify
"""

import logging
from datetime import datetime, timezone

from app.config import settings
from app.repositories.sqlite_repository import sqlite_repo
from app.services.ai_service import analyze_with_ai
from app.services.email_service import should_send_email, send_alert_email

logger = logging.getLogger(__name__)


def parse_alert(raw: dict) -> dict | None:
    """
    Extract important fields from a raw Wazuh alert.
    Returns None if the alert level is below the critical threshold.
    """
    rule = raw.get("rule", {})
    level = rule.get("level", 0)

    if level < settings.ALERT_MIN_LEVEL:
        return None

    return {
        "description": rule.get("description", "Alerte inconnue"),
        "level": level,
        "agent": raw.get("agent", {}).get("name", "unknown"),
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "raw_log": raw.get("full_log", ""),
        "source_ip": raw.get("data", {}).get("srcip", "Inconnue"),
        "groups": rule.get("groups", []),
    }


def process_alert(raw_alert: dict) -> dict | None:
    """
    Full processing pipeline for a single Wazuh alert.

    Steps:
      1. Parse — extract fields, filter by level
      2. Dedup — SHA-256 hash check
      3. AI — SambaNova DeepSeek analysis (if enabled)
      4. Save — insert into SQLite
      5. Email — SMTP notification (if cooldown allows)

    Returns the processed alert dict, or None if filtered/duplicated.
    """
    # Step 1: Parse
    alert_data = parse_alert(raw_alert)
    if alert_data is None:
        return None

    logger.info(
        "🚨 Critical alert detected! Level %d/15 | %s | Agent: %s",
        alert_data["level"], alert_data["description"], alert_data["agent"],
    )

    # Step 2: Deduplication
    alert_hash = sqlite_repo.compute_alert_hash(
        alert_data["description"],
        alert_data["agent"],
        alert_data["timestamp"],
    )
    if sqlite_repo.is_duplicate(alert_hash):
        logger.info("   ♻️  Duplicate detected — skipping")
        return None

    # Step 3: AI Analysis
    ai_analysis = ""
    if settings.AI_ANALYSIS_ENABLED:
        logger.info("   🤖 Running AI analysis...")
        ai_analysis = analyze_with_ai(alert_data)
    alert_data["ai_analysis"] = ai_analysis

    # Step 4: Save to SQLite
    notify = should_send_email(alert_data["description"])
    alert_data["notified"] = notify

    saved = sqlite_repo.save_critical_alert(alert_data)
    if saved:
        logger.info("   💾 Alert saved to SQLite")
    else:
        logger.warning("   ⚠️  Save failed (concurrent duplicate?)")
        return None

    # Step 5: Email Notification
    if notify:
        email_sent = send_alert_email(alert_data, ai_analysis)
        if not email_sent:
            logger.info("   📧 Email not sent (config or error)")
    else:
        logger.info("   ⏸️  Email cooldown active (%ds)", settings.EMAIL_COOLDOWN_SECONDS)

    return alert_data
