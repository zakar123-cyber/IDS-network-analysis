# 🛡️ BLACK WALL — Système de Détection d'Intrusions Pédagogique (PFA)

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

## 🔗 Déploiement AWS (Production)

> 📖 Pour un guide **détaillé étape par étape**, voir [`AWS_DEPLOYMENT_GUIDE.md`](AWS_DEPLOYMENT_GUIDE.md)

### 1. Configuration AWS Firewall (Security Group)
Ouvrez **deux ports** dans votre Security Group AWS :

| Type | Port | Rôle |
|------|------|------|
| Custom TCP | `8501` | Dashboard SIEM (Frontend Nginx) |
| Custom TCP | `8000` | API Backend (FastAPI) |

### 2. Déploiement des conteneurs
```bash
cd ~/IDS-network-analysis
cp .env.example .env      # Puis éditez avec vos clés API
docker compose up --build -d
```

### 3. Accès au Dashboard SOC
- **URL :** `http://<VOTRE_IP_PUBLIQUE_AWS>:8501`
- **Opérateur :** `admin`
- **Passphrase :** `blackwall2026`

### 4. Intégration Wazuh (2 étapes obligatoires)

**Étape A — Créer le script d'intégration :**
```bash
docker exec -it single-node-wazuh.manager-1 bash -c '
cat > /var/ossec/integrations/custom-blackwall << "EOF"
#!/bin/sh
ALERT_FILE=$1
HOOK_URL=$3
curl -s -X POST "$HOOK_URL" -H "Content-Type: application/json" -d @"$ALERT_FILE"
exit 0
EOF
chmod 750 /var/ossec/integrations/custom-blackwall
chown root:wazuh /var/ossec/integrations/custom-blackwall'
```

**Étape B — Ajouter la configuration webhook :**
Ajoutez ce bloc dans `/var/ossec/etc/ossec.conf` (avant `</ossec_config>`) :
```xml
<integration>
    <name>custom-blackwall</name>
    <hook_url>http://<VOTRE_IP_PRIVEE>:8000/webhook</hook_url>
    <level>8</level>
    <alert_format>json</alert_format>
</integration>
```
Puis redémarrez : `docker restart single-node-wazuh.manager-1`

### Niveaux d'alerte (Configuration recommandée)

| Paramètre | Valeur | Rôle |
|-----------|--------|------|
| Wazuh `<level>` | `8` | Seuil d'envoi vers le webhook |
| `ALERT_MIN_LEVEL` | `8` | Seuil d'affichage dashboard |
| `CRITICAL_ALERT_LEVEL` | `12` | Seuil pour IA + email |

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
