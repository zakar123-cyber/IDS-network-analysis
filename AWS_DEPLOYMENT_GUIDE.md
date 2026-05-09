# 🛡️ BLACK WALL — Guide de Déploiement AWS (Étape par Étape)

> Ce guide couvre le déploiement complet de BLACK WALL IDS sur une instance AWS EC2
> déjà équipée de Wazuh (Docker single-node). **Aucune étape n'est manquante.**

---

## Prérequis

- Instance AWS EC2 (Ubuntu 22.04+ recommandé)
- Docker et Docker Compose installés sur l'instance
- Wazuh Manager déjà déployé en Docker (single-node) sur la même instance
- Accès SSH à l'instance : `ssh -i <votre-cle.pem> ubuntu@<IP_PUBLIQUE>`

---

## Étape 1 — Configurer le Firewall AWS (Security Group)

AWS bloque **tous les ports** par défaut sauf le port 22 (SSH). Vous devez ouvrir deux ports supplémentaires.

1. Connectez-vous à la [Console AWS](https://console.aws.amazon.com/)
2. Allez dans **EC2 → Instances** et cliquez sur votre instance
3. En bas, cliquez sur l'onglet **Security**, puis sur le lien de votre **Security Group**
4. Cliquez sur **Edit inbound rules** → **Add rule**
5. Ajoutez ces **deux règles** :

| Type | Port Range | Source | Description |
|------|-----------|--------|-------------|
| Custom TCP | `8501` | `0.0.0.0/0` | Dashboard SIEM (Frontend) |
| Custom TCP | `8000` | `0.0.0.0/0` | API Backend (FastAPI) |

6. Cliquez sur **Save rules**

> ⚠️ **Si vous oubliez le port 8000**, le dashboard s'affichera mais restera vide
> (le frontend JavaScript ne pourra pas contacter l'API backend).

---

## Étape 2 — Cloner le projet sur l'instance AWS

```bash
# SSH dans votre instance
ssh -i <votre-cle.pem> ubuntu@<IP_PUBLIQUE>

# Cloner le dépôt (ou transférer via scp/sftp)
git clone https://github.com/<votre-repo>/IDS-network-analysis.git
cd IDS-network-analysis
```

---

## Étape 3 — Configurer le fichier `.env`

```bash
# Copier le fichier d'exemple
cp .env.example .env

# Éditer avec nano
nano .env
```

### Variables à personnaliser :

| Variable | Valeur | Description |
|----------|--------|-------------|
| `POSTGRES_PASSWORD` | `votre_mot_de_passe` | Mot de passe PostgreSQL |
| `SAMBANOVA_API_KEY` | `votre_cle_api` | Clé API SambaNova pour l'analyse IA |
| `SMTP_USER` | `votre_user_smtp` | Utilisateur SMTP (Mailtrap, Gmail, etc.) |
| `SMTP_PASSWORD` | `votre_password_smtp` | Mot de passe SMTP |
| `ALERT_EMAIL_FROM` | `from@example.com` | Adresse expéditeur |
| `ALERT_EMAIL_TO` | `to@example.com` | Adresse destinataire des alertes |
| `ALERT_MIN_LEVEL` | `8` | Seuil minimum pour afficher sur le dashboard |
| `CRITICAL_ALERT_LEVEL` | `12` | Seuil pour déclencher l'IA + email |

Sauvegardez : `Ctrl+O` → `Enter` → `Ctrl+X`

---

## Étape 4 — Démarrer BLACK WALL

```bash
docker compose up --build -d
```

### Vérifiez que les 3 conteneurs sont actifs :

```bash
docker compose ps
```

**Résultat attendu :**
```
NAME                 STATUS          PORTS
blackwall-db         Up (healthy)    0.0.0.0:5432->5432/tcp
blackwall-backend    Up              0.0.0.0:8000->8000/tcp
blackwall-frontend   Up              0.0.0.0:8501->80/tcp
```

> Si un conteneur n'est pas "Up", consultez les logs : `docker logs blackwall-backend`

---

## Étape 5 — Vérifier l'accès au Dashboard

1. Ouvrez votre navigateur web (sur votre PC, pas sur le serveur)
2. Accédez à : `http://<VOTRE_IP_PUBLIQUE_AWS>:8501`
3. Connectez-vous avec :
   - **Opérateur :** `admin`
   - **Passphrase :** `blackwall2026`

> Si la page ne charge pas (timeout), retournez à l'**Étape 1** — le port 8501 n'est pas ouvert.

---

## Étape 6 — Récupérer l'IP Privée AWS

Cette adresse IP est nécessaire pour la communication Docker-to-Docker entre Wazuh et BLACK WALL.

```bash
hostname -I | awk '{print $1}'
```

**Exemple de sortie :** `172.30.x.x votre ip privé`

> 📝 **Notez cette IP**, vous en aurez besoin dans les étapes suivantes.

---

## Étape 7 — Créer le script d'intégration Wazuh

Wazuh utilise un mécanisme `custom-*` qui nécessite **un script exécutable** dans `/var/ossec/integrations/`. Sans ce script, l'intégration est silencieusement ignorée.

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
chown root:wazuh /var/ossec/integrations/custom-blackwall
echo "✅ Script créé avec succès"'
```

### Vérification :
```bash
docker exec -it single-node-wazuh.manager-1 ls -la /var/ossec/integrations/custom-blackwall
```

**Résultat attendu :** `-rwxr-x--- 1 root wazuh 125 ... /var/ossec/integrations/custom-blackwall`

> ⚠️ **C'est l'étape la plus critique.** Si le script est absent, Wazuh n'enverra
> jamais les alertes à BLACK WALL, même si la configuration ossec.conf est correcte.

---

## Étape 8 — Configurer le webhook dans Wazuh

### Option A : Via commande sed (automatique)

Remplacez `172.30.x.x` par votre IP privée de l'Étape 6 :

```bash
docker exec -it single-node-wazuh.manager-1 bash -c '
sed -i "/<\/ossec_config>/i\\
  <integration>\\
      <name>custom-blackwall</name>\\
      <hook_url>http://172.30.x.x:8000/webhook</hook_url>\\
      <level>8</level>\\
      <alert_format>json</alert_format>\\
  </integration>" /var/ossec/etc/ossec.conf
echo "✅ Configuration ajoutée"'
```

### Option B : Via nano (manuel)

```bash
# Installer nano si absent
docker exec -it -u root single-node-wazuh.manager-1 bash -c \
  "yum install nano -y 2>/dev/null || apt-get install nano -y 2>/dev/null"

# Ouvrir le fichier
docker exec -it single-node-wazuh.manager-1 nano /var/ossec/etc/ossec.conf
```

Ajoutez ce bloc **juste avant** la dernière ligne `</ossec_config>` :

```xml
  <integration>
      <name>custom-blackwall</name>
      <hook_url>http://172.30.x.x:8000/webhook</hook_url>
      <level>8</level>
      <alert_format>json</alert_format>
  </integration>
```

Sauvegardez : `Ctrl+O` → `Enter` → `Ctrl+X`

### Vérification de la configuration :
```bash
docker exec -it single-node-wazuh.manager-1 grep -A5 'custom-blackwall' /var/ossec/etc/ossec.conf
```

> ⚠️ **Attention aux doublons !** Si vous exécutez l'Étape 8 plusieurs fois, vous
> risquez d'ajouter plusieurs blocs `<integration>`. Vérifiez qu'il n'y en a qu'un seul.

---

## Étape 9 — Redémarrer Wazuh

```bash
docker restart single-node-wazuh.manager-1
```

Attendez 10 secondes, puis vérifiez que tout fonctionne :

```bash
sleep 10 && docker exec -it single-node-wazuh.manager-1 bash -c '
echo "=== SCRIPT ===" && ls -la /var/ossec/integrations/custom-blackwall
echo "=== CONFIG ===" && grep -A5 "custom-blackwall" /var/ossec/etc/ossec.conf
echo "=== PROCESS ===" && ps aux | grep wazuh-integratord | grep -v grep'
```

**Les 3 vérifications doivent passer :**
- ✅ Script existe avec permissions `750` et propriétaire `root:wazuh`
- ✅ Configuration `custom-blackwall` présente dans ossec.conf
- ✅ Processus `wazuh-integratord` en cours d'exécution

---

## Étape 10 — Créer une sauvegarde de la configuration

Docker est **éphémère** : si le conteneur Wazuh est recréé, toutes les modifications
manuelles (script + ossec.conf) seront perdues. Créez une sauvegarde sur le disque dur de l'instance :

```bash
# Sauvegarder ossec.conf
docker cp single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf ~/wazuh_ossec_backup.conf

# Sauvegarder le script
docker cp single-node-wazuh.manager-1:/var/ossec/integrations/custom-blackwall ~/wazuh_custom_blackwall_backup.sh

echo "✅ Backups créés dans ~/wazuh_ossec_backup.conf et ~/wazuh_custom_blackwall_backup.sh"
```

### Restauration (si nécessaire après un `docker-compose down` de Wazuh) :
```bash
docker cp ~/wazuh_ossec_backup.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf
docker cp ~/wazuh_custom_blackwall_backup.sh single-node-wazuh.manager-1:/var/ossec/integrations/custom-blackwall
docker exec -it single-node-wazuh.manager-1 bash -c \
  'chmod 750 /var/ossec/integrations/custom-blackwall && chown root:wazuh /var/ossec/integrations/custom-blackwall'
docker restart single-node-wazuh.manager-1
```

---

## Étape 11 — Tester la pipeline complète

### Test 1 : Webhook manuel (vérifie le backend)

```bash
curl -X POST http://127.0.0.1:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-05-09T14:00:00Z",
    "rule": {
      "level": 10,
      "description": "SSH brute force test",
      "id": "5712",
      "groups": ["syslog","sshd","authentication_failed"]
    },
    "agent": {"name": "test-agent", "id": "001", "ip": "10.0.0.5"},
    "data": {"srcip": "192.168.1.100"},
    "full_log": "Failed password for root from 192.168.1.100 port 22 ssh2"
  }'
```

**Résultat attendu :** `{"status":"saved_to_history","alert":null}`

### Test 2 : Connectivité Wazuh → Backend

```bash
docker exec -it single-node-wazuh.manager-1 bash -c \
  "curl -s -o /dev/null -w '%{http_code}' http://172.30.x.x:8000/health"
```

**Résultat attendu :** `200`

### Test 3 : Attaques SSH réelles (depuis l'Agent VM)

```bash
# Sur la machine où l'agent Wazuh est installé :
for i in $(seq 1 20); do ssh sshtest$i@127.0.0.1 2>&1 || true; sleep 0.5; done
```

### Test 4 : Vérifier les logs du backend

```bash
docker logs blackwall-backend --tail 20 2>&1 | grep -i "saved\|detection\|POST\|webhook"
```

**Résultat attendu :** `Saved X detection(s) to PostgreSQL`

Ensuite, rafraîchissez le dashboard dans votre navigateur — les graphiques doivent se remplir !

---

## Étape 12 — Test de l'alerte critique (IA + Email)

Pour tester le pipeline complet (IA + notification email), injectez une alerte de niveau 14 :

```bash
curl -X POST http://127.0.0.1:8000/test-alert
```

**Résultat attendu :** `{"status":"success","message":"Alerte de test traitée avec succès."}`

Vérifiez votre boîte email (ou Mailtrap) pour la notification.

---

## Résumé de l'Architecture Déployée

```
┌─────────────────────────────────────────────────────────────┐
│                    Instance AWS EC2                          │
│                                                             │
│  ┌──────────────┐     ┌──────────────────────────────────┐  │
│  │  Wazuh       │     │  BLACK WALL (docker compose)     │  │
│  │  (Docker)    │     │                                  │  │
│  │              │     │  ┌───────────┐  ┌─────────────┐  │  │
│  │  Manager ────┼────►│  │ Backend   │  │ Frontend    │  │  │
│  │  integratord │HTTP │  │ :8000     │  │ :8501       │  │  │
│  │              │POST │  └─────┬─────┘  └─────────────┘  │  │
│  │  Agent       │     │        │                         │  │
│  │  (Suricata)  │     │  ┌─────▼─────┐                   │  │
│  │              │     │  │PostgreSQL │                   │  │
│  └──────────────┘     │  │ :5432     │                   │  │
│                       │  └───────────┘                   │  │
│                       └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │ SSH (22)                            │ HTTP (8501 + 8000)
         │                                    │
    ┌────┴────┐                          ┌────┴────┐
    │ Admin   │                          │ Browser │
    │ (CLI)   │                          │ (SOC)   │
    └─────────┘                          └─────────┘
```

---

## Dépannage

### Le dashboard s'affiche mais reste vide
- **Cause :** Le port `8000` n'est pas ouvert dans le Security Group AWS
- **Fix :** Ajoutez une règle `Custom TCP / 8000 / 0.0.0.0/0` dans les inbound rules

### Wazuh n'envoie pas d'alertes au webhook
- **Cause 1 :** Le script `/var/ossec/integrations/custom-blackwall` est absent
- **Cause 2 :** La config `<integration>` a été effacée (conteneur recréé)
- **Fix :** Refaire les Étapes 7, 8, et 9

### Le conteneur Wazuh ne démarre plus après modification
- **Cause :** Erreur de syntaxe XML dans `ossec.conf`
- **Fix :** Restaurer la sauvegarde (voir Étape 10)

### Les alertes arrivent au backend mais pas sur le dashboard
- **Cause :** Le frontend utilisait `localhost:8000` au lieu de l'IP publique
- **Fix :** La variable `BackendUrl` dans `dashboard.html` utilise désormais `window.location.hostname` automatiquement

### `wazuh-integratord` n'est pas dans la liste des processus
- **Cause :** Erreur dans la configuration XML
- **Fix :** Vérifiez les logs : `docker logs single-node-wazuh.manager-1 | tail -20`

---

## Niveaux d'alerte — Explication

| Niveau Wazuh | Catégorie | Exemples |
|:---:|-----------|----------|
| 0-3 | Info | Login réussi, démarrage de service |
| 4-7 | Faible | Erreur de mot de passe unique, scan basique |
| 8-9 | Moyen | Scans de ports multiples, modifications de fichiers |
| 10-11 | Élevé | Brute force SSH, échecs d'authentification répétés |
| 12-15 | **Critique** | Attaque confirmée, rootkit, exploitation active |

### Configuration recommandée pour la soutenance

| Paramètre | Fichier | Valeur | Effet |
|-----------|---------|--------|-------|
| `<level>` | `ossec.conf` (Wazuh) | `8` | Wazuh envoie les alertes level ≥ 8 au webhook |
| `STATIC_THRESHOLD_ALERT_LEVEL` | `.env` (Black Wall) | `8` | Le dashboard affiche les alertes level ≥ 8 |
| `ALERT_MIN_LEVEL` | `.env` (Black Wall) | `8` | Filtre minimum d'ingestion |
| `CRITICAL_ALERT_LEVEL` | `.env` (Black Wall) | `12` | Seules les alertes level ≥ 12 déclenchent l'IA et les emails |

---

*BLACK WALL IDS — Guide de Déploiement AWS — Projet de Fin d'Année (PFA) — 2026*
