"""
============================================
BLACK WALL — History Controller
============================================
API endpoints for data retrieval:
  GET /history         — Alert history from PostgreSQL
  GET /stats           — Aggregated statistics
  GET /critical-alerts — Critical alerts from SQLite
"""

import logging

from fastapi import APIRouter, Query

from app.repositories.postgres_repository import postgres_repo
from app.repositories.sqlite_repository import sqlite_repo

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/history")
def get_history(limit: int = Query(default=100)):
    """Retrieve alert history from the PostgreSQL database."""
    return {"alerts": postgres_repo.get_alert_history(limit)}


@router.get("/stats")
def get_statistics():
    """Aggregate and return global statistics."""
    return postgres_repo.get_stats()


@router.get("/critical-alerts")
def list_critical_alerts(limit: int = Query(default=50)):
    """
    Retrieve critical alerts (level >= 12) with AI analysis.
    Stored in SQLite, separate from the main dashboard history.
    """
    alerts = sqlite_repo.get_critical_alerts(limit)
    stats = sqlite_repo.get_stats()
    return {"alerts": alerts, "stats": stats}
