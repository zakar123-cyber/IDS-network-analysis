"""
============================================
BLACK WALL — Analyze Controller
============================================
API endpoints for file analysis:
  POST /analyze      — Upload and analyze JSON/CSV/PCAP files
  POST /analyze-ai   — Full AI-powered analysis via SambaNova
  GET  /scan-wazuh   — Scan shared volume for Wazuh logs
  POST /save-detections — Save detection results to database
"""

import csv
import io
import json
import logging
import os
import tempfile
import traceback
from datetime import datetime, timezone

import requests
from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks

from app.config import settings
from app.repositories.postgres_repository import postgres_repo
from app.services.detection_service import analyze_alerts
from app.services.pcap_service import perform_pcap_analysis
from app.services.alert_pipeline import process_alert
from app.utils.parsers import load_wazuh_logs

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/analyze")
async def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Parse and analyze an uploaded security log or network capture."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Fichier manquant.")

    filename = file.filename.lower()
    content = await file.read()

    alerts_json: list[dict] = []
    alerts_pcap: list[dict] = []

    try:
        # ── JSON / Log files ──
        if filename.endswith((".json", ".log")):
            text = content.decode("utf-8", errors="replace").strip()
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    alerts_json = data
                elif isinstance(data, dict):
                    alerts_json = [data]
            except json.JSONDecodeError:
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        try:
                            alerts_json.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        # ── CSV files ──
        elif filename.endswith((".csv", ".cvs")):
            text = content.decode("utf-8", errors="replace").strip()
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                level_str = row.get("Risk Score", row.get("level", "5"))
                try:
                    level = int(level_str)
                except ValueError:
                    level = 5

                alert = {
                    "timestamp": row.get("Timestamp", row.get(
                        "timestamp", datetime.now(timezone.utc).isoformat()
                    )),
                    "agent": {"name": row.get("Agent", row.get("agent", "CSV-Import"))},
                    "data": {"srcip": row.get("Source IP", row.get("srcip", "0.0.0.0"))},
                    "rule": {
                        "level": level,
                        "description": row.get("Detection Detail", row.get(
                            "description", "Imported from CSV row"
                        )),
                        "groups": [row.get("Attack Type", row.get("group", "csv_import"))],
                    },
                    "full_log": str(row),
                }
                alerts_json.append(alert)

        # ── PCAP files ──
        elif filename.endswith((".pcap", ".pcapng")):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            try:
                alerts_pcap = perform_pcap_analysis(tmp_path, file.filename)
            finally:
                os.unlink(tmp_path)

        else:
            raise HTTPException(status_code=400, detail="Format non supporté.")

        # ── Run detection engine ──
        results = analyze_alerts(alerts=alerts_json, pcap_alerts=alerts_pcap)

        # ── Persist to PostgreSQL ──
        try:
            saved = postgres_repo.save_detections(results["all_detections"])
            results["summary"]["saved_to_database"] = saved
        except Exception as db_err:
            logger.warning("Database save warning: %s", db_err)
            results["summary"]["database_warning"] = str(db_err)

        # ── Trigger email pipeline for JSON alerts ──
        for alert in alerts_json:
            background_tasks.add_task(process_alert, alert)

        return results

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Analysis failed: %s\n%s", e, traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze-ai")
async def analyze_file_ai(file: UploadFile = File(...)):
    """Full AI-powered analysis via SambaNova DeepSeek."""
    content = await file.read()
    text_content = content.decode("utf-8", errors="replace")

    if not settings.SAMBANOVA_API_KEY:
        raise HTTPException(status_code=500, detail="SAMBANOVA_API_KEY non configuré")

    headers = {
        "Authorization": f"Bearer {settings.SAMBANOVA_API_KEY}",
        "Content-Type": "application/json",
    }
    prompt = f"""Analyze the following security log data and detect all threats.
Return ONLY a valid JSON object with this structure:
{{
  "summary": {{
    "total_detections": <number>,
    "threat_level": "<Vert|Orange|Rouge>",
    "threat_label": "<string>",
    "average_risk_score": <number 0-100>,
    "ai_analysis_summary": "<2-3 sentence summary>"
  }},
  "all_detections": [
    {{
      "timestamp": "<ISO timestamp>",
      "detection_method": "Intelligence Artificielle (DeepSeek)",
      "detection_detail": "<technical explanation>",
      "attack_type": "<attack type name>",
      "attack_icon": "<emoji>",
      "risk_score": <0-100>,
      "ml_confidence": <0-99.9>,
      "source_ip": "<IP>",
      "target": "<target>",
      "explication_vulgarisee": "<plain language explanation>",
      "recommendation": "<security recommendation>",
      "agent_name": "<agent name>",
      "raw_log": "<log excerpt>"
    }}
  ]
}}

Log data:\n{text_content}"""

    payload = {
        "model": settings.SAMBANOVA_MODEL,
        "messages": [
            {"role": "system", "content": "You are an expert cybersecurity analyst. Respond with valid JSON only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "top_p": 0.1,
    }

    try:
        response = requests.post(settings.SAMBANOVA_API_URL, headers=headers, json=payload)
        response.raise_for_status()
    except Exception as req_err:
        raise HTTPException(status_code=502, detail=f"SambaNova API error: {req_err}")

    try:
        ai_data = response.json()
        ai_text = ai_data["choices"][0]["message"]["content"].strip()
        if ai_text.startswith("```json"):
            ai_text = ai_text[7:-3].strip()
        elif ai_text.startswith("```"):
            ai_text = ai_text[3:-3].strip()
        parsed = json.loads(ai_text)
    except Exception as parse_err:
        raise HTTPException(status_code=500, detail=f"AI response parse error: {parse_err}")

    try:
        postgres_repo.save_detections(parsed.get("all_detections", []))
    except Exception as e:
        parsed.setdefault("summary", {})["database_warning"] = str(e)

    return parsed


@router.get("/scan-wazuh")
def scan_wazuh_logs():
    """Scan the shared volume for Wazuh JSON log files."""
    wazuh_dir = settings.WAZUH_LOG_DIR
    if not os.path.exists(wazuh_dir):
        return {"message": "Dossier vide."}

    all_alerts: list[dict] = []
    for fname in os.listdir(wazuh_dir):
        fpath = os.path.join(wazuh_dir, fname)
        if os.path.isfile(fpath) and fname.endswith(".json"):
            all_alerts.extend(load_wazuh_logs(fpath))

    if not all_alerts:
        return {"message": "Aucune alerte trouvée."}

    results = analyze_alerts(alerts=all_alerts)
    postgres_repo.save_detections(results["all_detections"])
    return results


@router.post("/save-detections")
async def save_detections_endpoint(payload: dict):
    """Manually save detection results to the database."""
    try:
        saved = postgres_repo.save_detections(payload.get("detections", []))
        return {"saved": saved}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
