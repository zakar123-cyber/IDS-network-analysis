# ============================================
# BLACK WALL - Frontend Dockerfile
# ============================================
# Image légère Python 3.11 pour le dashboard Streamlit.

FROM python:3.11-slim

# Métadonnées
LABEL maintainer="BLACK WALL Team"
LABEL description="Frontend Dashboard pédagogique du système IDS BLACK WALL"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dossier de travail
WORKDIR /app

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# Exposition du port Streamlit
EXPOSE 8501

# Configuration Streamlit pour Docker
# - server.headless : pas de navigateur ouvert automatiquement
# - server.address : écoute sur toutes les interfaces
# - browser.gatherUsageStats : désactive la télémétrie
CMD ["streamlit", "run", "app.py", \
     "--server.headless=true", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--browser.gatherUsageStats=false"]
