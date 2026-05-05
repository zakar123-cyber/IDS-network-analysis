# ============================================
# BLACK WALL - Backend Dockerfile
# ============================================
# Image légère Python 3.11 pour le serveur FastAPI / Moteur IDS.

FROM python:3.11-slim

# Métadonnées
LABEL maintainer="BLACK WALL Team"
LABEL description="Backend API du système IDS pédagogique BLACK WALL"

# Variables d'environnement pour Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dossier de travail dans le conteneur
WORKDIR /app

# Installation des dépendances système nécessaires pour :
# - psycopg2 (client PostgreSQL)
# - scapy (analyse réseau / libpcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Création et activation de l'environnement virtuel (Venv)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copie et installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copie du code source de l'application
COPY . .

# Création du dossier pour les logs Wazuh (point de montage du volume)
RUN mkdir -p /app/wazuh_logs

# Exposition du port FastAPI
EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
