"""
============================================
BLACK WALL — AI Analysis Service
============================================
Integration with SambaNova DeepSeek API for AI-powered
threat analysis and security recommendations.
"""

import json
import logging

import requests

from app.config import settings

logger = logging.getLogger(__name__)


def analyze_with_ai(alert_data: dict) -> str:
    """
    Send alert data to SambaNova DeepSeek for AI analysis.
    Returns the AI's analysis text, or a warning message on failure.
    """
    if not settings.AI_ANALYSIS_ENABLED:
        return ""

    if not settings.SAMBANOVA_API_KEY:
        return "⚠️ Clé API SambaNova non configurée (SAMBANOVA_API_KEY)"

    prompt = (
        f"Tu es un analyste en cybersécurité expert. Une alerte critique de "
        f"niveau {alert_data['level']}/15 vient d'être déclenchée sur le système SIEM.\n\n"
        f"Informations de l'alerte :\n"
        f"- Description : {alert_data['description']}\n"
        f"- Niveau de sévérité : {alert_data['level']}/15\n"
        f"- Agent concerné : {alert_data['agent']}\n"
        f"- Timestamp : {alert_data['timestamp']}\n"
        f"- Log complet : {alert_data.get('raw_log', 'Non disponible')}\n"
        f"- IP source : {alert_data.get('source_ip', 'Inconnue')}\n\n"
        f"En 3-4 phrases concises, explique :\n"
        f"1. Quelle est cette attaque/menace et comment elle fonctionne\n"
        f"2. Pourquoi c'est dangereux pour l'infrastructure\n"
        f"3. Quelles actions immédiates prendre pour se protéger\n\n"
        f"Réponds directement sans introduction ni formatage spécial."
    )

    headers = {
        "Authorization": f"Bearer {settings.SAMBANOVA_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.SAMBANOVA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Tu es un expert en cybersécurité spécialisé dans l'analyse "
                    "d'alertes SIEM/IDS. Tu donnes des analyses concises, "
                    "techniques mais compréhensibles."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 500,
    }

    try:
        response = requests.post(
            settings.SAMBANOVA_API_URL,
            headers=headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        ai_text = data["choices"][0]["message"]["content"].strip()

        # Clean markdown formatting if present
        if ai_text.startswith("```"):
            lines = ai_text.split("\n")
            ai_text = "\n".join(lines[1:-1]) if len(lines) > 2 else ai_text

        logger.info("🤖 AI analysis received (%d chars)", len(ai_text))
        return ai_text

    except requests.exceptions.Timeout:
        logger.warning("AI API timeout (30s)")
        return "⚠️ Analyse IA indisponible (timeout)"
    except requests.exceptions.ConnectionError:
        logger.warning("AI API connection error")
        return "⚠️ Analyse IA indisponible (connexion impossible)"
    except requests.exceptions.HTTPError as e:
        logger.warning("AI API HTTP error: %s", e.response.status_code)
        return f"⚠️ Analyse IA indisponible (erreur HTTP {e.response.status_code})"
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        logger.warning("AI response parse error: %s", e)
        return "⚠️ Analyse IA indisponible (réponse invalide)"
    except Exception as e:
        logger.error("Unexpected AI error: %s", e)
        return f"⚠️ Analyse IA indisponible ({type(e).__name__})"
