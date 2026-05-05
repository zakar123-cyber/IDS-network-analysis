"""
============================================
BLACK WALL - Dashboard Pédagogique (app.py)
============================================
Interface Streamlit interactive pour visualiser les alertes.
Conforme au cahier des charges : Filtres, Export, Pédagogie.
"""

import os
import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import json
from pathlib import Path

# Configuration
st.set_page_config(page_title="BLACK WALL IDS", page_icon="🛡️", layout="wide")
BACKEND_URL = os.getenv("BACKEND_API_URL", "http://backend:8000")

# Styles via CSS
st.markdown("""
<style>
    .stApp { font-family: 'Inter', sans-serif; }
    .main-header {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 40%, #16213e 70%, #0f3460 100%);
        padding: 2rem; border-radius: 12px; margin-bottom: 2rem;
        border: 1px solid rgba(15, 52, 96, 0.5);
    }
    .main-header h1 { color: #e94560; font-weight: 800; font-size: 2.2rem; }
    .alert-card {
        background: #16213e; border-left: 4px solid #e94560;
        padding: 1rem; margin-bottom: 1rem; border-radius: 0 8px 8px 0;
    }
    .badge-ml { background: #9b59b6; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; }
    .badge-st { background: #3498db; color: white; padding: 2px 8px; border-radius: 12px; font-size: 0.8rem; }
</style>
""", unsafe_allow_html=True)

def call_backend(endpoint, method="GET", files=None, params=None):
    url = f"{BACKEND_URL}{endpoint}"
    try:
        if method == "POST": r = requests.post(url, files=files, params=params)
        else: r = requests.get(url, params=params)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Erreur de connexion au backend.")
        return None

# Sidebar
with st.sidebar:
    st.markdown("### 🧭 Navigation")
    page = st.radio("Aller à", ["📤 Analyse & Upload", "📜 Historique & Filtres", "📊 Statistiques", "🔬 Méthode & Limites (Pédagogie)"])

st.markdown('<div class="main-header"><h1>🛡️ BLACK WALL</h1><p>IDS Pédagogique - Analyse de Trafic Réseau & Logs</p></div>', unsafe_allow_html=True)


if page == "📤 Analyse & Upload":
    st.info("💡 Importez un fichier de trafic réseau (.pcap) ou de logs (.json) pour tester l'IDS.")
    uploaded_file = st.file_uploader("Fichier PCAP ou JSON", type=["json", "pcap", "pcapng"])
    notify_email = st.checkbox("Notify admins (run AI pipeline and send email)")

    if uploaded_file and st.button("🚀 Lancer l'analyse"):
        # If user requested notification, send the file to the webhook which runs the full pipeline
        if notify_email:
            with st.spinner("Envoi au pipeline IA + notification en cours..."):
                try:
                    text = uploaded_file.getvalue().decode('utf-8', errors='replace')
                    parsed = json.loads(text)
                except Exception:
                    st.error("Le fichier doit contenir du JSON valide pour activer la notification.")
                    parsed = None

                if parsed is not None:
                    # If the JSON is a list of alerts, POST each; if a single alert, post it directly
                    try:
                        if isinstance(parsed, list):
                            results = []
                            for item in parsed:
                                r = requests.post(f"{BACKEND_URL}/webhook", json=item)
                                results.append(r.json() if r and r.status_code == 200 else {"error": r.text if r else "no response"})
                        elif isinstance(parsed, dict):
                            r = requests.post(f"{BACKEND_URL}/webhook", json=parsed)
                            results = [r.json() if r and r.status_code == 200 else {"error": r.text if r else "no response"}]
                        else:
                            results = [{"error": "Unsupported JSON structure"}]

                        st.success("Envoi terminé. Résultats :")
                        st.json(results)
                    except Exception as e:
                        st.error(f"Erreur lors de l'appel au backend: {e}")
        else:
            with st.spinner("Analyse du trafic réseau en cours..."):
                res = call_backend("/analyze", method="POST", files={"file": (uploaded_file.name, uploaded_file.getvalue())})
            
        if not notify_email and res and res.get("all_detections"):
            st.success(f"Opération terminée. {res['summary']['total_detections']} menace(s) détectée(s).")
            for det in res["all_detections"]:
                badge = "badge-ml" if "IA" in det["detection_method"] else "badge-st"
                st.markdown(f"""
                <div class="alert-card">
                    <h4>{det['attack_icon']} {det['attack_type']} <span class="{badge}">{det['detection_method']}</span></h4>
                    <p><strong>Source :</strong> {det['source_ip']} → <strong>Cible :</strong> {det['target']}</p>
                    <p><em>Explication:</em> {det['explication_vulgarisee']}</p>
                    <p><strong>Détail IDS:</strong> {det['detection_detail']}</p>
                </div>
                """, unsafe_allow_html=True)
        elif res:
            st.success("Trafic analysé : Aucun comportement suspect détecté. (Trafic Normal)")


elif page == "📜 Historique & Filtres":
    st.markdown("## 📜 Historique et Recherche")
    history = call_backend("/history", params={"limit": 500})
    
    if history and history.get("alerts"):
        df = pd.DataFrame(history["alerts"])
        
        # Filtres
        col1, col2, col3 = st.columns(3)
        ip_filter = col1.text_input("Filtrer par IP Source")
        type_filter = col2.selectbox("Filtrer par Type", ["Tout"] + list(df['attack_type'].unique()))
        
        # Application filtres
        filtered_df = df.copy()
        if ip_filter: filtered_df = filtered_df[filtered_df['source_ip'].str.contains(ip_filter)]
        if type_filter != "Tout": filtered_df = filtered_df[filtered_df['attack_type'] == type_filter]
        
        st.dataframe(filtered_df[["detected_at", "attack_type", "detection_method", "source_ip", "risk_score"]])

        # Export CSV
        csv = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(label="📥 Exporter le rapport (CSV)", data=csv, file_name='rapport_alertes_blackwall.csv', mime='text/csv')
    else:
        st.warning("Aucune donnée dans l'historique.")


elif page == "📊 Statistiques":
    st.markdown("## 📊 Analyse et Comparatif")
    stats = call_backend("/stats")
    if stats:
        st.markdown("Dans un réseau normal, la distribution des paquets est uniforme. Ici, nous voyons clairement les pics d'activité suspecte.")
        
        col1, col2 = st.columns(2)
        with col1:
            fig = px.pie(values=list(stats['by_attack_type'].values()), names=list(stats['by_attack_type'].keys()), title="Types d'attaques")
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            fig2 = px.bar(x=list(stats['top_source_ips'].keys()), y=list(stats['top_source_ips'].values()), title="Activité par IP Source")
            st.plotly_chart(fig2, use_container_width=True)


elif page == "🔬 Méthode & Limites (Pédagogie)":
    st.markdown("## 📚 Cadre Méthodologique de l'IDS")
    
    st.markdown("""
    Dans le cadre de cette démonstration pédagogique, ce système implémente une logique de détection volontairement **explicite**. 
    Contrairement à un produit commercial (boîte noire), les règles ici sont structurées pour comprendre le *pourquoi* de la détection.
    
    ### 1. Extraction et Préparation des données PCAP
    Lors de l'import d'un fichier PCAP (Capture Réseau), BLACK WALL utilise la bibliothèque Python `Scapy` pour disséquer les paquets.
    Nous extrayons les attributs suivants : `IP Source`, `IP Destination`, `Port TCP/UDP`, et `Timestamp`.
    
    ### 2. Logique de Détection (Règles implémentées)
    * **Le Scan de Ports (Port Scan) :** Le script dresse l'inventaire des ports ciblés par une IP. Si `V(ports_uniques) >= 10` en quelques secondes vers la même cible, le motif suspect est identifié.
    * **Le Déni de Service (DoS/Flood) :** Le code calcule le ratio `Total_Paquets / Durée`. Si `Volume > 100 paquets/sec` de la part d'une unique IP, l'activité est classifiée "Flood".
    
    ### 3. Limites du Prototype
    * **Chiffrement :** Ce prototype n'inspecte pas le corps (Payload) des paquets chiffrés (HTTPS/TLS). La détection est basée sur les en-têtes (Headers) de la couche 3 et 4 (IP/TCP/UDP).
    * **Seuils Statiques :** Le risque de limitation d'une règle statique est le *Faux Positif*. Un serveur DNS interne très actif pourrait déclencher la règle de Flood si les seuils pédagogiques ne sont pas ajustés au contexte réel du laboratoire.
    * **Aucune action préventive (IPS) :** Il s'agit d'un IDS (Intrusion Detection System) et non d'un IPS (Prevention). Il détecte, note, loggue, mais ne bloque aucune adresse IP de lui-même pour des raisons de sécurité de laboratoire.
    """)
