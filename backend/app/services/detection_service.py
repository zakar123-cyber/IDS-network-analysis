"""
============================================
BLACK WALL — Detection Service
============================================
Core intrusion detection logic for Wazuh JSON alerts.
Two methods: static rules and simulated ML scoring.

Note: The ML detection uses a *simulated* confidence score
(pedagogical prototype). In production, replace detect_ml()
with a real trained model (e.g., scikit-learn RandomForest).
"""

import logging
import random
from datetime import datetime, timezone

from app.config import settings
from app.utils.attack_catalog import ATTACK_EXPLANATIONS
from app.utils.classifiers import classify_attack_type

logger = logging.getLogger(__name__)


def detect_static(alerts: list[dict]) -> list[dict]:
    """
    Static rule-based detection.
    Flags alerts whose Wazuh level meets or exceeds the configured threshold.
    """
    results = []
    threshold = settings.STATIC_THRESHOLD_ALERT_LEVEL

    for alert in alerts:
        rule = alert.get("rule", {})
        rule_level = rule.get("level", 0)

        if rule_level >= threshold:
            attack_type = classify_attack_type(
                rule.get("groups", []), rule.get("description", "")
            )
            info = ATTACK_EXPLANATIONS.get(attack_type, ATTACK_EXPLANATIONS["unknown"])

            results.append({
                "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "detection_method": "Règle Statique (Logs)",
                "detection_detail": f"Niveau Wazuh ({rule_level}/15) >= au seuil ({threshold}/15).",
                "attack_type": info["name"],
                "attack_icon": info["icon"],
                "risk_score": min(100, int((rule_level / 15) * 100)),
                "source_ip": alert.get("data", {}).get("srcip", "Inconnue"),
                "target": alert.get("data", {}).get(
                    "dstuser", alert.get("data", {}).get("url", "Serveur")
                ),
                "explication_vulgarisee": info["explanation"],
                "recommendation": info["recommendation"],
                "agent_name": alert.get("agent", {}).get("name", "System"),
                "raw_log": alert.get("full_log", ""),
            })

    logger.info("Static detection: %d alert(s) flagged from %d input(s).", len(results), len(alerts))
    return results


def detect_ml(alerts: list[dict]) -> list[dict]:
    """
    Simulated ML-based detection (pedagogical prototype).

    Uses the Wazuh rule level as a feature to generate a simulated
    confidence score. In a real system, this would call a trained
    scikit-learn model with proper feature extraction.
    """
    results = []

    for alert in alerts:
        rule = alert.get("rule", {})
        rule_level = rule.get("level", 0)

        # Simulated confidence: base score from level + random noise
        ml_confidence = min(99.9, ((rule_level / 15) * 70) + random.uniform(10, 30))
        ml_confidence = round(ml_confidence, 1)

        if ml_confidence >= 75.0:
            attack_type = classify_attack_type(
                rule.get("groups", []), rule.get("description", "")
            )
            info = ATTACK_EXPLANATIONS.get(attack_type, ATTACK_EXPLANATIONS["unknown"])

            results.append({
                "timestamp": alert.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "detection_method": "Intelligence Artificielle (ML)",
                "detection_detail": (
                    f"Comportement anormal détecté. Notre modèle (Decision Tree simulé) "
                    f"a une confiance de {ml_confidence}% que l'action est malveillante."
                ),
                "ml_confidence": ml_confidence,
                "attack_type": info["name"],
                "attack_icon": info["icon"],
                "risk_score": min(100, int(ml_confidence)),
                "source_ip": alert.get("data", {}).get("srcip", "Inconnue"),
                "target": alert.get("data", {}).get(
                    "dstuser", alert.get("data", {}).get("url", "Serveur")
                ),
                "explication_vulgarisee": info["explanation"],
                "recommendation": info["recommendation"],
                "agent_name": alert.get("agent", {}).get("name", "System"),
                "raw_log": "IA: " + alert.get("full_log", ""),
            })

    logger.info("ML detection: %d alert(s) flagged from %d input(s).", len(results), len(alerts))
    return results


def analyze_alerts(
    alerts: list[dict] | None = None,
    pcap_alerts: list[dict] | None = None,
) -> dict:
    """
    Combined analysis entry point.
    Merges results from static rules, ML, and PCAP analysis.
    """
    all_detections = []

    if alerts:
        all_detections.extend(detect_static(alerts))
        all_detections.extend(detect_ml(alerts))

    if pcap_alerts:
        all_detections.extend(pcap_alerts)

    # Compute threat summary
    if not all_detections:
        threat_level = "Vert"
        threat_label = "✅ Aucune menace détectée"
        avg_risk = 0
    else:
        avg_risk = sum(d["risk_score"] for d in all_detections) / len(all_detections)
        if avg_risk >= 75:
            threat_level = "Rouge"
            threat_label = "🔴 CRITIQUE - Menaces sévères détectées"
        elif avg_risk >= 50:
            threat_level = "Orange"
            threat_label = "🟠 ATTENTION - Activité suspecte significative"
        else:
            threat_level = "Vert"
            threat_label = "🟢 NORMAL - Activité à faible risque"

    summary = {
        "total_detections": len(all_detections),
        "threat_level": threat_level,
        "threat_label": threat_label,
        "average_risk_score": round(avg_risk, 1),
    }

    logger.info(
        "Analysis complete: %d detection(s), threat=%s, avg_risk=%.1f",
        len(all_detections), threat_level, avg_risk,
    )

    return {"summary": summary, "all_detections": all_detections}
