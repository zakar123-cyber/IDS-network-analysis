# 🛡️ BLACK WALL — Système de Détection d'Intrusions Pédagogique

> **BLACK WALL** est un dashboard pédagogique de type IDS/SIEM (Intrusion Detection System / Security Information & Event Management) conçu pour les établissements scolaires et universitaires. Il analyse le trafic réseau (PCAP) et les alertes (JSON Wazuh), applique des règles de détection statiques et un scoring ML simulé, puis restitue les résultats de manière "vulgarisée" via une console analytique SOC.

---

## 🎯 Objectif (Cadre Académique)

- **Analyse du Trafic :** Analyse native de captures réseaux via Python/Scapy.
- **Logique Explicite :** Scripts de détection clairs mettant en avant *le pourquoi* (ratio de paquets, scan de ports multiples).
- **Restitution Vulgarisée :** Recommandations et explications accessibles avec un système de Risk Score (0-100).
- **Analyse IA :** Intégration SambaNova DeepSeek pour des analyses de menaces en langage naturel.

---

## 🚀 Démarrage Rapide

### Prérequis
- [Docker](https://docs.docker.com/get-docker/) et [Docker Compose](https://docs.docker.com/compose/install/)
- Python 3.11+ (optionnel — pour générer des attaques de démonstration)

### Lancement

```bash
# 1. Démarrez l'architecture complète (Backend + Frontend + DB)
docker compose up --build -d

# 2. Accès aux services :
#    → Console SIEM :  http://localhost:8501
#    → API Backend  :  http://localhost:8000/docs

# 3. Arrêt et suppression :
docker compose down -v
```

---

## 🎬 Scénario de Démonstration (Soutenance)

1. Générez un fichier de test dans `wazuh_logs/` :
   ```bash
   cd wazuh_logs/
   pip install scapy
   python generate_pcap.py
   ```
2. Connectez-vous à **`http://localhost:8501`** (Identifiants : `admin` / `blackwall2026`)
3. Uploadez `demo_attaque.pcap` ou un fichier `.json` Wazuh via le bouton Upload.
4. Les graphiques s'animent en fonction du niveau d'attaque détecté.

---

## 🔗 Intégration Wazuh (Production)

Le backend BLACK WALL est prêt à recevoir les alertes d'un vrai manager Wazuh en direct. Deux méthodes sont supportées :

### Option 1 : Webhook (Cloud to Local — AWS vers PC)
Si votre Wazuh est hébergé sur le Cloud (AWS, Azure) et que votre dashboard tourne en local sur votre PC, AWS ne peut pas joindre votre IP privée (`192.168.x.x`). 
1. Utilisez **Ngrok** (`ngrok http 8000`) pour obtenir une URL publique temporaire, ou **Tailscale** pour un VPN Mesh avec une IP fixe.
2. Dans le fichier `/var/ossec/etc/ossec.conf` de votre manager Wazuh (AWS), ajoutez :
   ```xml
   <integration>
       <name>custom-blackwall</name>
       <!-- Remplacez par votre URL Ngrok ou IP Tailscale -->
       <hook_url>https://VOTRE_URL_NGROK/webhook</hook_url>
       <level>12</level> <!-- Envoi uniquement des alertes critiques -->
       <alert_format>json</alert_format>
   </integration>
   ```
3. Redémarrez Wazuh : `sudo systemctl restart wazuh-manager`.

### Option 2 : Volume Partagé (Même machine)
Si Wazuh et BLACK WALL sont installés sur la **même machine**, modifiez simplement votre `docker-compose.yml` pour lier le vrai dossier Wazuh :
```yaml
    volumes:
      # Ligne à modifier sous le service "backend" :
      - /var/ossec/logs/alerts:/app/wazuh_logs:ro
```
Le thread `wazuh_monitor.py` lira automatiquement le fichier `/app/wazuh_logs/alerts.json` en temps réel.

---

## 🏗️ Architecture (Docker — 3 services)

```
BLACK WALL (Docker Network : ids-network)
├── 🖥️ Frontend (Nginx)       → Port 8501 → Console SIEM (TailwindCSS, Chart.js)
├── ⚙️ Backend  (FastAPI)      → Port 8000 → Moteur de détection + API REST
├── 🗄️ PostgreSQL              → Port 5432 → Historique des alertes
└── 📁 wazuh_logs/             → Volume partagé (alerts.json)
```

---

## 📂 Structure du Code Source

```
PFA IDS/
├── docker-compose.yml
├── .env
│
├── BLACKWALL/                     # Frontend SIEM (Nginx)
│   ├── dashboard.html             # Console SOC interactive
│   ├── index.html                 # Landing page
│   ├── login.html                 # Page de connexion
│   ├── rules.html                 # Documentation des règles Wazuh
│   ├── scenarios.html             # Scénarios d'attaque pédagogiques
│   └── report.html                # Méthodologie académique
│
├── backend/
│   ├── main.py                    # App factory (slim — monte les routers)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/                       # ← Package principal (architecture en couches)
│       ├── config/
│       │   └── settings.py        # Variables d'environnement centralisées
│       ├── models/
│       │   ├── entities.py        # ORM SQLAlchemy (AlertRecord)
│       │   └── schemas.py         # Pydantic validation (request/response)
│       ├── repositories/          # DAO Pattern (abstraction base de données)
│       │   ├── base.py            # Interface abstraite AlertRepository
│       │   ├── postgres_repository.py
│       │   └── sqlite_repository.py
│       ├── services/              # Logique métier
│       │   ├── detection_service.py   # Règles statiques + ML simulé
│       │   ├── pcap_service.py        # Analyse Scapy (port scan, DoS)
│       │   ├── ai_service.py          # Intégration SambaNova DeepSeek
│       │   ├── email_service.py       # Notifications SMTP
│       │   └── alert_pipeline.py      # Pipeline: parse → dedup → AI → save → email
│       ├── controllers/           # FastAPI Routers (endpoints)
│       │   ├── analyze_controller.py  # /analyze, /analyze-ai, /scan-wazuh
│       │   ├── history_controller.py  # /history, /stats, /critical-alerts
│       │   └── monitor_controller.py  # /monitor/status, /test-alert, /webhook
│       ├── workers/
│       │   └── wazuh_monitor.py   # File tailer (tail -f) daemon thread
│       └── utils/
│           ├── attack_catalog.py  # Dictionnaire d'attaques (explications FR)
│           ├── classifiers.py     # Classification par type d'attaque
│           └── parsers.py         # Parsing JSON Wazuh + timestamps
│
├── wazuh_logs/                    # Données de test
│   ├── generate_pcap.py           # Générateur PCAP (trafic normal + attaques)
│   ├── generate_alerts.py         # Générateur d'alertes Wazuh JSON
│   └── sample_alert.json          # Exemples (brute force, web scan)
│
└── frontend_legacy/               # Ancien frontend Streamlit (archivé)
    └── app.py
```

---

## 📡 Endpoints Backend

| Méthode | Endpoint           | Description                                           |
|---------|--------------------|-------------------------------------------------------|
| GET     | `/health`          | Healthcheck Docker                                    |
| POST    | `/analyze`         | Upload et analyse (JSON / CSV / PCAP)                 |
| POST    | `/analyze-ai`      | Analyse complète via SambaNova DeepSeek                |
| GET     | `/scan-wazuh`      | Scan automatique du volume partagé                    |
| GET     | `/history`         | Historique des alertes (PostgreSQL)                    |
| GET     | `/stats`           | Statistiques agrégées                                 |
| GET     | `/critical-alerts` | Alertes critiques avec analyse IA (SQLite)            |
| POST    | `/webhook`         | Réception webhook Wazuh (temps réel)                  |
| POST    | `/test-alert`      | Injection d'une alerte de test                        |
| GET     | `/monitor/status`  | État du moniteur de fichiers Wazuh                    |

---

## 🧱 Patterns d'Architecture

### DAO (Data Access Object)
Le backend utilise un pattern DAO pour abstraire l'accès aux données. L'interface `AlertRepository` dans `repositories/base.py` définit le contrat. Pour ajouter MySQL, créez un `MySQLRepository(AlertRepository)` — aucun changement dans les services ou controllers.

### Séparation en Couches
```
Controllers → Services → Repositories → Database
    (HTTP)    (Logique)    (DAO)         (PG/SQLite)
```

### Dual Database
- **PostgreSQL** : Historique complet des alertes (dashboard)
- **SQLite** : Alertes critiques (level ≥ 12) + analyse IA + déduplication SHA-256

---

## 🔧 Règles de Détection

| Règle | Méthode | Seuil |
|-------|---------|-------|
| **Port Scan** | PCAP (Scapy) | IP → ≥ 10 ports uniques sur même cible |
| **DoS / Flood** | PCAP (Scapy) | > 100 paquets/sec depuis même IP |
| **Alerte Statique** | JSON (Wazuh) | Niveau ≥ 8 (configurable via `.env`) |
| **ML Simulé** | JSON (Wazuh) | Confiance simulée ≥ 75% |

---

## 📝 Technologies

| Couche | Technologie |
|--------|-------------|
| Backend | FastAPI, Uvicorn, Python 3.11 |
| Détection | Scapy, Règles statiques, ML simulé |
| IA | SambaNova DeepSeek V3.1 |
| Base de données | PostgreSQL 16 (SQLAlchemy), SQLite 3 |
| Frontend | HTML/CSS/JS, TailwindCSS, Chart.js, Lucide |
| Infrastructure | Docker, Docker Compose, Nginx |
| Email | SMTP (Mailtrap sandbox) |

---

*BLACK WALL IDS — Projet de Fin d'Année (PFA) — 2026*
