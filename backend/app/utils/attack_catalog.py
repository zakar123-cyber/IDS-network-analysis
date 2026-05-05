"""
============================================
BLACK WALL — Attack Explanations Catalog
============================================
Pedagogical dictionary mapping attack types to human-readable
explanations and security recommendations (French).
"""

ATTACK_EXPLANATIONS: dict[str, dict] = {
    "brute_force": {
        "name": "Attaque par Force Brute (Brute Force)",
        "icon": "🔨",
        "explanation": (
            "Un attaquant essaie de deviner votre mot de passe "
            "en testant des milliers de combinaisons automatiquement."
        ),
        "recommendation": (
            "Activez l'authentification à deux facteurs (2FA) "
            "et utilisez des mots de passe complexes."
        ),
    },
    "sql_injection": {
        "name": "Injection SQL (SQLi)",
        "icon": "💉",
        "explanation": (
            "Le pirate insère du code malveillant dans un formulaire "
            "pour tromper la base de données."
        ),
        "recommendation": "Utilisez des requêtes paramétrées (prepared statements).",
    },
    "web_scan": {
        "name": "Scan Web / Reconnaissance",
        "icon": "🔍",
        "explanation": (
            "Exploration du site à la recherche de fichiers cachés "
            "ou failles connues."
        ),
        "recommendation": "Cacher les pages d'administration et utiliser un WAF.",
    },
    "dos_ddos": {
        "name": "Déni de Service (DoS/DDoS) / Inondation",
        "icon": "🌊",
        "explanation": (
            "L'attaquant submerge votre réseau avec un énorme volume "
            "de trafic pour le bloquer."
        ),
        "recommendation": "Limitation de débit (Rate limiting) et pare-feu.",
    },
    "port_scan": {
        "name": "Scan de Ports",
        "icon": "🚪",
        "explanation": (
            "Quelqu'un essaie toutes vos 'portes' (ports réseau) "
            "pour voir lesquelles sont ouvertes et vulnérables."
        ),
        "recommendation": "Fermez les ports inutilisés dans le pare-feu externe.",
    },
    "unknown": {
        "name": "Activité Suspecte Non Classifiée",
        "icon": "⚠️",
        "explanation": "Le comportement ne correspond à aucune catégorie connue.",
        "recommendation": "Examinez les logs détaillés manuellement.",
    },
}
