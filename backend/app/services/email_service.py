"""
============================================
BLACK WALL — Email Notification Service
============================================
SMTP email notifications for critical security alerts.
Includes rate limiting per alert type to prevent spam.
"""

import logging
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.config import settings
from app.repositories.sqlite_repository import sqlite_repo

logger = logging.getLogger(__name__)


def should_send_email(description: str) -> bool:
    """
    Rate-limiting check: only send email if the cooldown period
    has elapsed for this specific alert type.
    """
    last_time_str = sqlite_repo.get_last_notified_time(description)
    if last_time_str is None:
        return True

    try:
        last_time = datetime.strptime(last_time_str, "%Y-%m-%d %H:%M:%S")
        elapsed = (datetime.now(timezone.utc).replace(tzinfo=None) - last_time).total_seconds()
        return elapsed >= settings.EMAIL_COOLDOWN_SECONDS
    except (ValueError, TypeError):
        return True


def send_alert_email(alert_data: dict, ai_analysis: str = "") -> bool:
    """
    Send an HTML email notification for a critical alert.
    Returns True if sent successfully, False otherwise.
    """
    if not all([settings.SMTP_HOST, settings.SMTP_USER,
                settings.SMTP_PASSWORD, settings.ALERT_EMAIL_TO]):
        logger.info("📧 Email not configured (missing SMTP variables)")
        return False

    subject = f"🚨 Alerte SIEM Critique — Niveau {alert_data.get('level', '?')}/15"

    html_body = f"""
    <html>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #16213e; border-radius: 12px; overflow: hidden; border: 1px solid #e94560;">
            <div style="background: linear-gradient(135deg, #e94560, #c23152); padding: 20px; text-align: center;">
                <h1 style="margin: 0; font-size: 22px; color: white;">🚨 BLACK WALL — Alerte Critique</h1>
            </div>
            <div style="padding: 24px;">
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <tr><td style="padding: 10px; border-bottom: 1px solid #2a3a5c; color: #8892b0; width: 140px;">📋 Description</td>
                        <td style="padding: 10px; border-bottom: 1px solid #2a3a5c; font-weight: bold;">{alert_data.get('description', 'N/A')}</td></tr>
                    <tr><td style="padding: 10px; border-bottom: 1px solid #2a3a5c; color: #8892b0;">⚠️ Sévérité</td>
                        <td style="padding: 10px; border-bottom: 1px solid #2a3a5c;">
                            <span style="background: #e94560; color: white; padding: 3px 10px; border-radius: 12px; font-weight: bold;">
                                Niveau {alert_data.get('level', '?')} / 15</span></td></tr>
                    <tr><td style="padding: 10px; border-bottom: 1px solid #2a3a5c; color: #8892b0;">🖥️ Agent</td>
                        <td style="padding: 10px; border-bottom: 1px solid #2a3a5c;">{alert_data.get('agent', 'N/A')}</td></tr>
                    <tr><td style="padding: 10px; border-bottom: 1px solid #2a3a5c; color: #8892b0;">🌐 IP Source</td>
                        <td style="padding: 10px; border-bottom: 1px solid #2a3a5c;">{alert_data.get('source_ip', 'Inconnue')}</td></tr>
                </table>
                <div style="background: #0a0e1a; border-radius: 8px; padding: 14px; margin-bottom: 20px; border-left: 3px solid #e94560;">
                    <p style="margin: 0 0 6px 0; color: #8892b0; font-size: 12px;">📄 Log brut</p>
                    <code style="color: #64ffda; font-size: 13px; word-break: break-all;">{alert_data.get('raw_log', 'Non disponible')}</code>
                </div>
                {"" if not ai_analysis or ai_analysis.startswith("⚠️") else f'''
                <div style="background: #1a1040; border-radius: 8px; padding: 14px; border-left: 3px solid #7c3aed;">
                    <p style="margin: 0 0 6px 0; color: #a78bfa; font-size: 12px;">🤖 Analyse IA (DeepSeek)</p>
                    <p style="margin: 0; color: #c4b5fd; font-size: 14px; line-height: 1.5;">{ai_analysis}</p>
                </div>'''}
            </div>
            <div style="padding: 14px; text-align: center; color: #4a5568; font-size: 11px; border-top: 1px solid #2a3a5c;">
                BLACK WALL IDS — Notification automatique
            </div>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.ALERT_EMAIL_FROM
    msg["To"] = settings.ALERT_EMAIL_TO
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(
                settings.ALERT_EMAIL_FROM,
                settings.ALERT_EMAIL_TO.split(","),
                msg.as_string(),
            )
        logger.info("📧 Email sent to %s", settings.ALERT_EMAIL_TO)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("❌ SMTP authentication failed")
        return False
    except smtplib.SMTPException as e:
        logger.error("❌ SMTP error: %s", e)
        return False
    except Exception as e:
        logger.error("❌ Unexpected email error: %s", e)
        return False
