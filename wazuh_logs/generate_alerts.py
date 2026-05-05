"""
============================================
BLACK WALL - Générateur d'alertes Wazuh (generate_alerts.py)
============================================
Deux modes d'utilisation :

  1. Mode batch (par défaut) :
     python generate_alerts.py
     → Génère 100 alertes dans new_test_alerts.json

  2. Mode simulation en temps réel :
     python generate_alerts.py --simulate
     → Appende des alertes une par une dans alerts.json
     → Simule le comportement réel de Wazuh
     → Inclut des alertes critiques (level ≥ 12) pour tester le pipeline

  3. Mode simulation avec chemin personnalisé :
     python generate_alerts.py --simulate --output ./wazuh_logs/alerts.json
"""

import json
import random
import time
import argparse
import os
from datetime import datetime, timedelta


# ============================================
# Scénarios d'attaque
# ============================================

AGENTS = [
    {"id": "001", "name": "ubuntu-desktop", "ip": "192.168.1.10"},
    {"id": "005", "name": "database-srv", "ip": "10.0.5.20"},
    {"id": "009", "name": "nginx-proxy", "ip": "172.16.10.5"},
    {"id": "012", "name": "e-commerce-app", "ip": "172.16.10.12"},
]

ATTACK_SCENARIOS = [
    # --- Alertes de niveau ÉLEVÉ (12-15) → déclenchent le pipeline critique ---
    {
        "type": "Brute Force (Critique)",
        "rule_id": "5712",
        "level": 12,
        "desc": "sshd: brute force attack detected.",
        "groups": ["syslog", "sshd", "authentication_failed", "brute_force"],
        "srcip": "185.220.101.44",
        "logs": [
            "Failed password for root from {ip} port 22 ssh2",
            "Invalid user admin from {ip} port 22",
        ],
    },
    {
        "type": "Rootkit Detected",
        "rule_id": "510",
        "level": 14,
        "desc": "Host-based anomaly detection event (rootkit).",
        "groups": ["ossec", "rootcheck", "rootkit"],
        "srcip": "0.0.0.0",
        "logs": [
            "Rootkit 'Adore' detected by the presence of file '/usr/lib/libt0rn.so'.",
            "Anomalous hidden file detected: /dev/.hdd",
        ],
    },
    {
        "type": "Trojan Detected",
        "rule_id": "550",
        "level": 13,
        "desc": "Integrity checksum changed — possible trojan.",
        "groups": ["ossec", "syscheck", "trojan"],
        "srcip": "0.0.0.0",
        "logs": [
            "Integrity checksum changed for: '/usr/bin/sshd'",
            "File '/etc/passwd' ownership changed from root to nobody",
        ],
    },
    {
        "type": "Privilege Escalation",
        "rule_id": "5403",
        "level": 15,
        "desc": "Multiple sudo authentication failures — possible privilege escalation.",
        "groups": ["syslog", "sudo", "authentication_failed", "privilege_escalation"],
        "srcip": "10.0.5.99",
        "logs": [
            "user yassine : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/yassine ; USER=root ; COMMAND=/bin/bash",
            "ALERT: unauthorized sudo attempt by user www-data",
        ],
    },
    # --- Alertes de niveau MOYEN (6-11) → ne déclenchent PAS le pipeline critique ---
    {
        "type": "SQL Injection",
        "rule_id": "31103",
        "level": 9,
        "desc": "SQL Injection attempt detected.",
        "groups": ["web", "attack", "sql_injection"],
        "srcip": "45.133.1.20",
        "logs": [
            "GET /search.php?query=1' OR '1'='1 HTTP/1.1",
            "POST /api/v1/user/profile id=admin'--",
        ],
    },
    {
        "type": "Web Scan",
        "rule_id": "31101",
        "level": 6,
        "desc": "Web server 404 error (Scan Activity).",
        "groups": ["web", "accesslog", "web_scan"],
        "srcip": "193.106.31.5",
        "logs": [
            "GET /admin/ HTTP/1.1 404",
            "GET /.env HTTP/1.1 404",
            "GET /wp-admin/ HTTP/1.1 404",
        ],
    },
    # --- Alertes de niveau BAS (1-5) → bruit de fond normal ---
    {
        "type": "Login Success",
        "rule_id": "5501",
        "level": 3,
        "desc": "User logged in successfully (Policy Monitoring).",
        "groups": ["syslog", "auth", "access"],
        "srcip": "192.168.1.50",
        "logs": ["Accepted password for yassine from 192.168.1.50 port 54321 ssh2"],
    },
]


def generate_single_alert(scenario=None, agent=None):
    """Génère une seule alerte Wazuh au format JSON."""
    if scenario is None:
        scenario = random.choice(ATTACK_SCENARIOS)
    if agent is None:
        agent = random.choice(AGENTS)

    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    return {
        "timestamp": timestamp,
        "rule": {
            "id": scenario["rule_id"],
            "level": scenario["level"],
            "description": scenario["desc"],
            "groups": scenario["groups"],
        },
        "agent": agent,
        "data": {
            "srcip": scenario["srcip"],
            "program_name": "blackwall-engine",
        },
        "full_log": random.choice(scenario["logs"]).format(ip=scenario["srcip"]),
    }


def generate_random_alerts(count=50):
    """Génère un lot d'alertes aléatoires (mode batch)."""
    alerts = []
    base_time = datetime.now() - timedelta(hours=2)

    for i in range(count):
        scenario = random.choice(ATTACK_SCENARIOS)
        agent = random.choice(AGENTS)
        timestamp = (base_time + timedelta(minutes=i * 2)).strftime(
            "%Y-%m-%dT%H:%M:%S.000+0000"
        )

        alert = {
            "timestamp": timestamp,
            "rule": {
                "id": scenario["rule_id"],
                "level": scenario["level"],
                "description": scenario["desc"],
                "groups": scenario["groups"],
            },
            "agent": agent,
            "data": {
                "srcip": scenario["srcip"],
                "program_name": "blackwall-engine",
            },
            "full_log": random.choice(scenario["logs"]).format(ip=scenario["srcip"]),
        }
        alerts.append(alert)

    return alerts


# ============================================
# Mode Simulation Temps Réel
# ============================================

def simulate_realtime(output_path: str, interval: float = 3.0):
    """
    Simule le comportement de Wazuh en appendant des alertes
    une par une dans le fichier alerts.json.

    Le monitor de BLACK WALL va détecter chaque nouvelle ligne
    et traiter les alertes critiques (level ≥ 12).

    Args:
        output_path: Chemin vers le fichier alerts.json
        interval: Délai entre chaque alerte (secondes)
    """
    # Créer le dossier si nécessaire
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Pondération : plus d'alertes normales que critiques (réaliste)
    # ~ 30% critiques, 70% normales
    critical_scenarios = [s for s in ATTACK_SCENARIOS if s["level"] >= 12]
    normal_scenarios = [s for s in ATTACK_SCENARIOS if s["level"] < 12]

    print("=" * 60)
    print("🔄 BLACK WALL — Simulation d'alertes Wazuh en temps réel")
    print("=" * 60)
    print(f"   📁 Fichier : {output_path}")
    print(f"   ⏱️  Intervalle : {interval}s entre chaque alerte")
    print(f"   🔴 Scénarios critiques (≥12) : {len(critical_scenarios)}")
    print(f"   🟢 Scénarios normaux (<12) : {len(normal_scenarios)}")
    print(f"\n   Appuyez sur Ctrl+C pour arrêter.\n")

    count = 0
    critical_count = 0

    try:
        while True:
            # Choisir un scénario avec pondération
            if random.random() < 0.3:
                scenario = random.choice(critical_scenarios)
            else:
                scenario = random.choice(normal_scenarios)

            alert = generate_single_alert(scenario)
            count += 1

            # Écrire en mode append (NDJSON — une ligne JSON par alerte)
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")

            level = alert["rule"]["level"]
            is_critical = level >= 12
            icon = "🔴" if is_critical else "🟢"

            if is_critical:
                critical_count += 1

            print(
                f"  {icon} [{count:04d}] Level {level:2d}/15 | "
                f"{alert['agent']['name']:20s} | "
                f"{alert['rule']['description'][:50]}"
            )

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n🛑 Simulation arrêtée.")
        print(f"   Total alertes générées : {count}")
        print(f"   Dont critiques (≥12)   : {critical_count}")


# ============================================
# Point d'entrée
# ============================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Générateur d'alertes Wazuh pour BLACK WALL"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Mode simulation temps réel (append continu dans alerts.json)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Chemin du fichier de sortie",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Intervalle entre les alertes en secondes (défaut: 3s)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Nombre d'alertes à générer en mode batch (défaut: 100)",
    )

    args = parser.parse_args()

    if args.simulate:
        # Mode temps réel : simule Wazuh
        output = args.output or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "alerts.json"
        )
        simulate_realtime(output, interval=args.interval)
    else:
        # Mode batch : génère un fichier JSON
        output = args.output or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "new_test_alerts.json"
        )
        alerts = generate_random_alerts(args.count)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)
        print(f"✅ {args.count} alertes générées dans {output}")
