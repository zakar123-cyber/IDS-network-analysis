"""
============================================
BLACK WALL — SQLAlchemy ORM Entities
============================================
Database table definitions. Currently a single table for alert history.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, Text, DateTime, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config.settings import DATABASE_URL

# ── SQLAlchemy setup ──
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AlertRecord(Base):
    """
    Represents a detected alert stored in the PostgreSQL database.
    Each row corresponds to one detection (static rule, ML, or PCAP-based)
    recorded by the BLACK WALL engine.
    """
    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # Timestamps
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Detection metadata
    detection_method = Column(String(50))
    detection_detail = Column(Text)

    # Wazuh rule info
    rule_id = Column(String(20))
    rule_description = Column(String(500))

    # Attack classification
    attack_type = Column(String(100), index=True)
    risk_score = Column(Integer)
    ml_confidence = Column(Float, nullable=True)

    # Source & target
    source_ip = Column(String(45), index=True)
    target = Column(String(255))
    agent_name = Column(String(100))

    # Pedagogical fields
    explication_vulgarisee = Column(Text)
    recommendation = Column(Text)

    # Raw log for reference
    raw_log = Column(Text)

    def __repr__(self) -> str:
        return (
            f"<AlertRecord(id={self.id}, type='{self.attack_type}', "
            f"risk={self.risk_score}, method='{self.detection_method}')>"
        )
