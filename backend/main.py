"""
============================================
BLACK WALL — API Backend (main.py)
============================================
Slim application factory.
All business logic lives in app/ subpackages.
This file only wires together: lifespan, middleware, and routers.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ── Configure logging (before any other import) ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("blackwall")

# ── Application imports ──
from app.config.settings import log_config_summary
from app.repositories.postgres_repository import postgres_repo
from app.repositories.sqlite_repository import sqlite_repo
from app.workers.wazuh_monitor import create_and_start_monitor, get_monitor_instance
from app.controllers import analyze_controller, history_controller, monitor_controller


# ═══════════════════════════════════════════
# Lifespan: startup / shutdown
# ═══════════════════════════════════════════
@asynccontextmanager
async def lifespan(application: FastAPI):
    """
    Startup: connect DBs → init tables → start monitor.
    Shutdown: stop monitor gracefully.
    """
    logger.info("=" * 50)
    logger.info("  BLACK WALL — Starting up...")
    logger.info("=" * 50)
    log_config_summary()

    # ── PostgreSQL (with retry) ──
    max_retries = 10
    for attempt in range(1, max_retries + 1):
        try:
            postgres_repo.init_db()
            break
        except Exception as e:
            if attempt == max_retries:
                logger.error("❌ PostgreSQL unavailable after %d attempts.", max_retries)
                raise
            logger.warning(
                "⏳ PostgreSQL not ready (attempt %d/%d): %s — retrying in 3s...",
                attempt, max_retries, e,
            )
            time.sleep(3)

    # ── SQLite ──
    sqlite_repo.init_db()

    # ── Wazuh file monitor ──
    create_and_start_monitor()

    logger.info("✅ BLACK WALL backend is ready.")
    logger.info("=" * 50)

    yield  # ← Application runs here

    # ── Shutdown ──
    monitor = get_monitor_instance()
    if monitor:
        monitor.stop()
    logger.info("BLACK WALL backend shut down cleanly.")


# ═══════════════════════════════════════════
# App factory
# ═══════════════════════════════════════════
app = FastAPI(
    title="BLACK WALL — IDS/SIEM API",
    description="Pedagogical Intrusion Detection System powered by Wazuh, Scapy, and AI.",
    version="4.2.0",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount routers ──
app.include_router(analyze_controller.router, tags=["Analysis"])
app.include_router(history_controller.router, tags=["History"])
app.include_router(monitor_controller.router, tags=["Monitor"])


# ── Root endpoints ──
@app.get("/", tags=["Health"])
def root():
    return {
        "service": "BLACK WALL — IDS/SIEM Backend",
        "status": "operational",
        "version": "4.2.0",
        "endpoints": [
            "/analyze", "/analyze-ai", "/scan-wazuh",
            "/history", "/stats", "/critical-alerts",
            "/monitor/status", "/test-alert", "/webhook",
        ],
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "service": "blackwall-backend"}
