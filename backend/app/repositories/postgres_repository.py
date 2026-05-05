"""
============================================
BLACK WALL — PostgreSQL Repository
============================================
Concrete DAO implementation using SQLAlchemy + PostgreSQL.
Handles the main alert_history table for the dashboard.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import func

from app.repositories.base import AlertRepository
from app.models.entities import Base, SessionLocal, engine, AlertRecord
from app.utils.parsers import parse_timestamp

logger = logging.getLogger(__name__)


class PostgresRepository(AlertRepository):
    """PostgreSQL-backed alert storage via SQLAlchemy ORM."""

    def init_db(self) -> None:
        """Create all tables if they don't exist."""
        Base.metadata.create_all(bind=engine)
        logger.info("✅ PostgreSQL tables initialized.")

    def save_detections(self, detections: list[dict]) -> int:
        """Persist a batch of detections into alert_history."""
        db = SessionLocal()
        count = 0
        try:
            for det in detections:
                record = AlertRecord(
                    timestamp=parse_timestamp(det.get("timestamp")),
                    detection_method=det.get("detection_method", ""),
                    detection_detail=det.get("detection_detail", ""),
                    rule_id=det.get("rule_id", ""),
                    rule_description=det.get("rule_description", ""),
                    attack_type=det.get("attack_type", ""),
                    risk_score=det.get("risk_score", 0),
                    ml_confidence=det.get("ml_confidence"),
                    source_ip=det.get("source_ip", ""),
                    target=det.get("target", ""),
                    agent_name=det.get("agent_name", ""),
                    explication_vulgarisee=det.get("explication_vulgarisee", ""),
                    recommendation=det.get("recommendation", ""),
                    raw_log=det.get("raw_log", ""),
                )
                db.add(record)
                count += 1
            db.commit()
            logger.info("Saved %d detection(s) to PostgreSQL.", count)
        except Exception as e:
            db.rollback()
            logger.error("Failed to save detections: %s", e)
            raise
        finally:
            db.close()
        return count

    def get_alert_history(self, limit: int = 100) -> list[dict]:
        """Retrieve the most recent alerts ordered by detection time."""
        db = SessionLocal()
        try:
            records = (
                db.query(AlertRecord)
                .order_by(AlertRecord.detected_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                    "detection_method": r.detection_method,
                    "detection_detail": r.detection_detail,
                    "rule_id": r.rule_id,
                    "rule_description": r.rule_description,
                    "attack_type": r.attack_type,
                    "risk_score": r.risk_score,
                    "ml_confidence": r.ml_confidence,
                    "source_ip": r.source_ip,
                    "target": r.target,
                    "agent_name": r.agent_name,
                    "explication_vulgarisee": r.explication_vulgarisee,
                    "recommendation": r.recommendation,
                    "raw_log": r.raw_log,
                }
                for r in records
            ]
        finally:
            db.close()

    def get_stats(self) -> dict:
        """Aggregate statistics from the alert_history table."""
        db = SessionLocal()
        try:
            total = db.query(AlertRecord).count()

            type_counts = (
                db.query(AlertRecord.attack_type, func.count(AlertRecord.id))
                .group_by(AlertRecord.attack_type)
                .all()
            )
            method_counts = (
                db.query(AlertRecord.detection_method, func.count(AlertRecord.id))
                .group_by(AlertRecord.detection_method)
                .all()
            )
            top_ips = (
                db.query(AlertRecord.source_ip, func.count(AlertRecord.id))
                .group_by(AlertRecord.source_ip)
                .order_by(func.count(AlertRecord.id).desc())
                .limit(10)
                .all()
            )
            avg_risk = db.query(func.avg(AlertRecord.risk_score)).scalar() or 0

            return {
                "total_alerts": total,
                "by_attack_type": {t: c for t, c in type_counts},
                "by_detection_method": {m: c for m, c in method_counts},
                "top_source_ips": {ip: c for ip, c in top_ips},
                "average_risk_score": round(float(avg_risk), 1),
            }
        finally:
            db.close()


# ── Module-level singleton ──
postgres_repo = PostgresRepository()
