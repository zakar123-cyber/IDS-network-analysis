"""
============================================
BLACK WALL — PCAP Analysis Service
============================================
Deep packet inspection using Scapy for network traffic files.
Detects port scans and DoS/flood patterns.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import rdpcap, IP, TCP, UDP

from app.utils.attack_catalog import ATTACK_EXPLANATIONS

logger = logging.getLogger(__name__)


def perform_pcap_analysis(pcap_path: str, filename: str) -> list[dict]:
    """
    Analyze a PCAP file for intrusion indicators.

    Detection rules:
      - Port Scan: IP contacts >= 10 unique ports on a single target
      - DoS/Flood: Packet rate > 100 pkt/sec from a single IP
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.error("Failed to read PCAP file %s: %s", pcap_path, e)
        return []

    alerts = []

    # Collect network statistics
    ip_packet_count: dict[str, int] = defaultdict(int)
    ip_target_ports: dict[tuple, set] = defaultdict(set)
    first_seen: dict[str, float] = defaultdict(lambda: float("inf"))
    last_seen: dict[str, float] = defaultdict(float)

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_time = float(pkt.time)

            ip_packet_count[src_ip] += 1
            first_seen[src_ip] = min(first_seen[src_ip], pkt_time)
            last_seen[src_ip] = max(last_seen[src_ip], pkt_time)

            if TCP in pkt:
                ip_target_ports[(src_ip, dst_ip)].add(pkt[TCP].dport)
            elif UDP in pkt:
                ip_target_ports[(src_ip, dst_ip)].add(pkt[UDP].dport)

    # Rule 1: Port Scan Detection
    for (src_ip, dst_ip), ports in ip_target_ports.items():
        if len(ports) >= 10:
            info = ATTACK_EXPLANATIONS["port_scan"]
            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "detection_method": "Règle Statique (Réseau)",
                "detection_detail": (
                    f"Analyse PCAP: {src_ip} a scanné {len(ports)} ports "
                    f"sur la machine {dst_ip}."
                ),
                "attack_type": info["name"],
                "attack_icon": info["icon"],
                "risk_score": 85,
                "source_ip": src_ip,
                "target": dst_ip,
                "explication_vulgarisee": info["explanation"],
                "recommendation": info["recommendation"],
                "agent_name": f"PCAP Analyzer ({filename})",
                "raw_log": f"[PCAP] Ports ciblés : {list(ports)[:5]}...",
            })
            logger.warning("Port scan detected: %s → %s (%d ports)", src_ip, dst_ip, len(ports))

    # Rule 2: DoS / Flood Detection
    for src_ip, count in ip_packet_count.items():
        duration = last_seen[src_ip] - first_seen[src_ip]
        if duration > 0:
            rate = count / duration
            if rate > 100:
                info = ATTACK_EXPLANATIONS["dos_ddos"]
                alerts.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "detection_method": "Règle Statique (Réseau)",
                    "detection_detail": (
                        f"Analyse PCAP: Flood détecté depuis {src_ip} "
                        f"avec un taux de {rate:.1f} paquets/sec."
                    ),
                    "attack_type": info["name"],
                    "attack_icon": info["icon"],
                    "risk_score": 95,
                    "source_ip": src_ip,
                    "target": "Réseau Interne",
                    "explication_vulgarisee": info["explanation"],
                    "recommendation": info["recommendation"],
                    "agent_name": f"PCAP Analyzer ({filename})",
                    "raw_log": f"[PCAP] IP: {src_ip} | Total paquets: {count}",
                })
                logger.warning("DoS/Flood detected: %s (%.1f pkt/sec)", src_ip, rate)

    logger.info("PCAP analysis of %s: %d alert(s) generated.", filename, len(alerts))
    return alerts
