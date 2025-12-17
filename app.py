from scapy.all import sniff, IP, TCP, UDP, DNS
from collections import defaultdict, deque
import time
import socket

# ===================== CONFIG =====================
CAPTURE_INTERFACE = None  # None = default
TIME_WINDOW = 10
FLOOD_THRESHOLD = 120
MAX_SCORE = 100
SCORE_DECAY = 5
DECAY_INTERVAL = 15

# ===================== STORAGE =====================
traffic_window = defaultdict(deque)
threat_scores = defaultdict(int)
last_decay = time.time()

# ===================== THREAT INTELLIGENCE =====================
THREAT_DB = {
    "Traffic flood anomaly": {
        "label": "Traffic Flood / DoS-like Behavior",
        "explanation": "This source is generating an unusually high volume of packets in a short period, which may indicate traffic flooding.",
        "severity": "LOW"
    },
    "Port scanning behavior": {
        "label": "Port Scanning (Reconnaissance)",
        "explanation": "Multiple ports are being probed, commonly observed during reconnaissance activity.",
        "severity": "HIGH"
    }
}

# ===================== HELPERS =====================
def is_private_ip(ip):
    return (
        ip.startswith("192.168.") or
        ip.startswith("10.") or
        (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
    )

def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

def decay_scores():
    global last_decay
    now = time.time()
    if now - last_decay >= DECAY_INTERVAL:
        for ip in list(threat_scores.keys()):
            threat_scores[ip] = max(0, threat_scores[ip] - SCORE_DECAY)
        last_decay = now

# ===================== OUTPUT =====================
def print_dns(src, qname):
    print(f"🌐 DNS Query  | {src} → {qname}")

def print_mdns(src, service):
    print(f"🟢 mDNS (Local Service) | {src} → {service}")

def print_http(src, dst):
    domain = resolve_domain(dst)
    if domain:
        print(f"🌍 HTTP Req   | {src} → {domain}")

def report_threat(ip, points, reason):
    info = THREAT_DB.get(reason)
    if not info:
        return

    threat_scores[ip] = min(MAX_SCORE, threat_scores[ip] + points)
    score = threat_scores[ip]

    print(f"🚨 RISK LEVEL: {risk_level(score)}")
    print(f"IP Address : {ip}")
    print(f"Threat     : {info['label']}")
    print(f"Reason     : {info['explanation']}")
    print(f"Score      : {score}")
    print("-" * 70)

# ===================== PACKET ANALYZER =====================
def analyze_packet(packet):
    decay_scores()

    if not packet.haslayer(IP):
        return

    ip = packet[IP]
    src = ip.src
    dst = ip.dst
    now = time.time()

    traffic_window[src].append(now)
    while traffic_window[src] and now - traffic_window[src][0] > TIME_WINDOW:
        traffic_window[src].popleft()

    # DNS
    if packet.haslayer(DNS) and packet[DNS].qd:
        qname = packet[DNS].qd.qname.decode(errors="ignore")
        if qname.endswith(".local."):
            print_mdns(src, qname)
        else:
            print_dns(src, qname)

    # HTTP / HTTPS
    if packet.haslayer(TCP) and packet[TCP].dport in (80, 443):
        print_http(src, dst)

    # ===================== FLOOD LOGIC =====================
    if len(traffic_window[src]) > FLOOD_THRESHOLD:

        # Ignore internal hosts
        if is_private_ip(src):
            print(f"🟢 Normal Internal Burst | {src}")
            traffic_window[src].clear()
            return

        # Ignore outbound HTTPS cloud traffic
        if packet.haslayer(TCP) and packet[TCP].sport == 443:
            print(f"🟢 Cloud Service Traffic | {src}")
            traffic_window[src].clear()
            return

        report_threat(src, 25, "Traffic flood anomaly")
        traffic_window[src].clear()

# ===================== START =====================
print("\n🔥 Advanced Explainable Network Threat Analyzer Started")
print("🛡 SOC-style | Context-aware | Explainable | Low False Positives\n")

sniff(
    iface=CAPTURE_INTERFACE,
    prn=analyze_packet,
    store=False
)
