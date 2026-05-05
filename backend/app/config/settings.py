"""
============================================
BLACK WALL — Centralized Configuration
============================================
All environment variables are loaded and validated once here.
No other module should call os.getenv() directly.
"""

import os
import logging

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════
# Database (PostgreSQL — main alert history)
# ═══════════════════════════════════════════
DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql://blackwall_user:changeme_strong_password@db:5432/blackwall_db",
)

# ═══════════════════════════════════════════
# AI Analysis (SambaNova DeepSeek)
# ═══════════════════════════════════════════
SAMBANOVA_API_KEY: str = os.getenv("SAMBANOVA_API_KEY", "")
SAMBANOVA_API_URL: str = os.getenv(
    "SAMBANOVA_API_URL", "https://api.sambanova.ai/v1/chat/completions"
)
SAMBANOVA_MODEL: str = os.getenv("SAMBANOVA_MODEL", "DeepSeek-V3.1")
AI_ANALYSIS_ENABLED: bool = os.getenv("AI_ANALYSIS_ENABLED", "true").lower() == "true"

# ═══════════════════════════════════════════
# Email Notifications (SMTP)
# ═══════════════════════════════════════════
SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL_FROM: str = os.getenv("ALERT_EMAIL_FROM", SMTP_USER)
ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")
EMAIL_COOLDOWN_SECONDS: int = int(os.getenv("EMAIL_COOLDOWN_SECONDS", "300"))

# ═══════════════════════════════════════════
# Detection Thresholds
# ═══════════════════════════════════════════
STATIC_THRESHOLD_ALERT_LEVEL: int = int(os.getenv("STATIC_THRESHOLD_ALERT_LEVEL", "8"))
STATIC_THRESHOLD_CONNECTIONS: int = int(os.getenv("STATIC_THRESHOLD_CONNECTIONS", "50"))
ALERT_MIN_LEVEL: int = int(os.getenv("ALERT_MIN_LEVEL", "12"))

# ═══════════════════════════════════════════
# Wazuh Log Surveillance
# ═══════════════════════════════════════════
WAZUH_ALERTS_PATH: str = os.getenv("WAZUH_ALERTS_PATH", "/app/wazuh_logs/alerts.json")
WAZUH_LOG_DIR: str = "/app/wazuh_logs"


def log_config_summary() -> None:
    """Log a summary of the active configuration at startup."""
    logger.info("Configuration loaded:")
    logger.info("  Database URL: %s", DATABASE_URL.split("@")[-1])
    logger.info("  AI Enabled: %s (Model: %s)", AI_ANALYSIS_ENABLED, SAMBANOVA_MODEL)
    logger.info("  SMTP Host: %s", SMTP_HOST)
    logger.info("  Alert Min Level: %d", ALERT_MIN_LEVEL)
    logger.info("  Wazuh Path: %s", WAZUH_ALERTS_PATH)
