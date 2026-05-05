from scapy.all import IP, TCP, wrpcap
import time
import random

print("Génération du PCAP de démonstration...")

packets = []

# --- 1. Trafic Normal ---
# Quelques requêtes HTTP basiques
for _ in range(20):
    src_port = random.randint(10000, 60000)
    pkt = IP(src="192.168.1.50", dst="192.168.1.100") / TCP(sport=src_port, dport=80, flags="S")
    packets.append(pkt)

# --- 2. Attaque : Scan de Ports (IP -> multiples ports) ---
# L'IP 10.0.0.99 scanne 15 ports différents
print("Injection Scénario : Scan de ports (10.0.0.99)...")
target_ip = "192.168.1.200"
for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]:
    pkt = IP(src="10.0.0.99", dst=target_ip) / TCP(sport=random.randint(10000, 60000), dport=port, flags="S")
    packets.append(pkt)

# --- 3. Attaque : DoS / SYN Flood (Beaucoup de paquets en très peu de temps) ---
print("Injection Scénario : DoS / TCP Flood (172.16.0.44)...")
for _ in range(150):
    # En quelques millisecondes virtuellement, 150 paquets envoyés
    pkt = IP(src="172.16.0.44", dst="192.168.1.10") / TCP(sport=random.randint(10000, 60000), dport=80, flags="S")
    packets.append(pkt)

# Mélanger légèrement si besoin (optionnel) et sauvegarder
print("Création du fichier 'demo_attaque.pcap'...")
wrpcap("demo_attaque.pcap", packets)
print("✅ Fichier généré avec succès ! Vous pouvez l'uploader dans BLACK WALL.")
