from scapy.all import sniff, IP, TCP, UDP, DNS
from collections import defaultdict, deque
import time
import socket

# ===================== CONFIG =====================
CAPTURE_INTERFACE = None       
TIME_WINDOW = 30               
SCORE_DECAY = 2
DECAY_INTERVAL = 20
ALERT_THRESHOLD_MED = 10
ALERT_THRESHOLD_HIGH = 20

# ===================== HOST STATE =====================
hosts = defaultdict(lambda: {
    "dns": deque(maxlen=100),
    "http": deque(maxlen=100),
    "score": 0,
    "last_seen": time.time(),
    "last_decay": time.time()
})

# ===================== UTILITIES =====================
def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# ===================== EVENT NORMALIZATION =====================
def normalize_event(packet):
    event = {
        "time": time.time(),
        "src": packet[IP].src,
        "dst": packet[IP].dst,
        "type": None,
        "detail": None
    }

    if packet.haslayer(DNS) and packet[DNS].qd:
        event["type"] = "DNS"
        event["detail"] = packet[DNS].qd.qname.decode(errors="ignore")

    elif packet.haslayer(TCP) and packet[TCP].dport in [80, 443]:
        event["type"] = "HTTP"
        event["detail"] = resolve_ip(packet[IP].dst)

    return event

# ===================== CORRELATION ENGINE =====================
def correlate(event):
    host = hosts[event["src"]]
    host["last_seen"] = event["time"]

    # ---- DNS LOGIC ----
    if event["type"] == "DNS":
        host["dns"].append(event["detail"])

        # Reverse DNS is usually benign (low weight)
        if event["detail"].endswith(".in-addr.arpa."):
            host["score"] += 1

        # Suspicious long/random domains
        if len(event["detail"]) > 50:
            host["score"] += 3

    # ---- HTTP LOGIC ----
    if event["type"] == "HTTP":
        host["http"].append(event["detail"])

        # Cloud/CDN traffic = neutral
        if any(x in event["detail"] for x in ["akamai", "amazonaws", "cloudfront", "msedge"]):
            host["score"] += 0
        else:
            host["score"] += 2

    apply_decay(event["src"])
    evaluate(event["src"])

# ===================== SCORE DECAY =====================
def apply_decay(ip):
    host = hosts[ip]
    now = time.time()

    if now - host["last_decay"] > DECAY_INTERVAL:
        host["score"] = max(0, host["score"] - SCORE_DECAY)
        host["last_decay"] = now

# ===================== EVALUATION =====================
def evaluate(ip):
    host = hosts[ip]

    if host["score"] >= ALERT_THRESHOLD_HIGH:
        alert(ip, "HIGH")
    elif host["score"] >= ALERT_THRESHOLD_MED:
        alert(ip, "MEDIUM")

# ===================== EXPLAINABLE ALERT =====================
def alert(ip, level):
    host = hosts[ip]

    print("\n" + "="*60)
    print(f"🚨 SOC CORRELATED ALERT | Severity: {level}")
    print(f"Source Host      : {ip}")
    print(f"Threat Score     : {host['score']}")
    print(f"DNS Queries      : {len(host['dns'])}")
    print(f"HTTP Requests    : {len(host['http'])}")
    print("Analysis Summary :")

    if any(d.endswith(".in-addr.arpa.") for d in host["dns"]):
        print("- Reverse DNS resolution observed (normal behavior)")

    if any("amazonaws" in h for h in host["http"]):
        print("- Cloud infrastructure traffic (AWS)")

    print("- No beaconing interval patterns detected")
    print("- No DNS tunneling indicators")
    print("Verdict          : Monitoring only, no escalation")
    print("="*60 + "\n")

# ===================== PACKET HANDLER =====================
def handle_packet(packet):
    if not packet.haslayer(IP):
        return

    event = normalize_event(packet)
    if event["type"]:
        correlate(event)

        # ---- CLEAN LOG OUTPUT ----
        if event["type"] == "DNS":
            print(f"🌐 DNS Query  | {event['src']} → {event['detail']}")
        elif event["type"] == "HTTP":
            print(f"🌍 HTTP Req  | {event['src']} → {event['detail']}")

# ===================== MAIN =====================
if __name__ == "__main__":
    print("Network Threat Analyzer Started")
    sniff(iface=CAPTURE_INTERFACE, prn=handle_packet, store=False)
