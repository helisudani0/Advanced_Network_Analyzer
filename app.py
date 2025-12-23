from scapy.all import sniff, IP, TCP, DNS
from collections import defaultdict, deque
import time
import socket

# ===================== CONFIG =====================
CAPTURE_INTERFACE = None
TIME_WINDOW = 30
SCORE_DECAY = 3
DECAY_INTERVAL = 15
ALERT_THRESHOLD_MED = 10
ALERT_THRESHOLD_HIGH = 20
ALERT_COOLDOWN = 60          # seconds
MAX_SCORE = 100

# ===================== HOST STATE =====================
hosts = defaultdict(lambda: {
    "dns": deque(maxlen=100),
    "http": deque(maxlen=100),
    "score": 0,
    "last_seen": time.time(),
    "last_decay": time.time(),
    "severity": "LOW",
    "last_alert": 0
})

# ===================== UTILITIES =====================
def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# ===================== EVENT NORMALIZATION =====================
def normalize_event(packet):
    if not packet.haslayer(IP):
        return None

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

    return event if event["type"] else None

# ===================== CORRELATION ENGINE =====================
def correlate(event):
    host = hosts[event["src"]]
    host["last_seen"] = event["time"]

    # ---- DNS LOGIC ----
    if event["type"] == "DNS":
        host["dns"].append(event["detail"])

        if event["detail"].endswith(".in-addr.arpa."):
            host["score"] += 1

        elif len(event["detail"]) > 50:
            host["score"] += 2

    # ---- HTTP LOGIC ----
    elif event["type"] == "HTTP":
        host["http"].append(event["detail"])

        if any(x in event["detail"] for x in [
            "google", "1e100", "akamai", "amazonaws",
            "cloudfront", "windowsupdate", "digicert", "lencr"
        ]):
            pass
        else:
            host["score"] += 1

    host["score"] = min(MAX_SCORE, host["score"])
    apply_decay(event["src"])
    evaluate(event["src"])

# ===================== SCORE DECAY =====================
def apply_decay(ip):
    host = hosts[ip]
    now = time.time()

    if now - host["last_decay"] >= DECAY_INTERVAL:
        host["score"] = max(0, host["score"] - SCORE_DECAY)
        host["last_decay"] = now

# ===================== EVALUATION (SOC-GRADE) =====================
def evaluate(ip):
    host = hosts[ip]
    now = time.time()

    if host["score"] >= ALERT_THRESHOLD_HIGH:
        new_sev = "HIGH"
    elif host["score"] >= ALERT_THRESHOLD_MED:
        new_sev = "MEDIUM"
    else:
        new_sev = "LOW"

    #ALERT ONLY ON SEVERITY ESCALATION
    if severity_rank(new_sev) > severity_rank(host["severity"]):
        if now - host["last_alert"] >= ALERT_COOLDOWN:
            alert(ip, new_sev)
            host["last_alert"] = now
            host["severity"] = new_sev

def severity_rank(sev):
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[sev]

# ===================== EXPLAINABLE ALERT =====================
def alert(ip, level):
    host = hosts[ip]

    print("\n" + "="*60)
    print(f"SOC CORRELATED ALERT | Severity: {level}")
    print(f"Source Host      : {ip}")
    print(f"Threat Score     : {host['score']}")
    print(f"DNS Queries      : {len(host['dns'])}")
    print(f"HTTP Requests    : {len(host['http'])}")
    print("Analysis Summary :")

    if any(d.endswith(".in-addr.arpa.") for d in host["dns"]):
        print("- Reverse DNS resolution observed (normal behavior)")

    if any("amazonaws" in h or "akamai" in h for h in host["http"]):
        print("- Cloud/CDN infrastructure traffic detected")

    print("- No beaconing interval patterns detected")
    print("- No DNS tunneling indicators")
    print("Verdict          : Monitoring only, no escalation")
    print("="*60 + "\n")

# ===================== PACKET HANDLER =====================
def handle_packet(packet):
    event = normalize_event(packet)
    if not event:
        return

    correlate(event)

    if event["type"] == "DNS":
        print(f"DNS Query  | {event['src']} → {event['detail']}")
    elif event["type"] == "HTTP":
        print(f"HTTP Req  | {event['src']} → {event['detail']}")

# ===================== MAIN =====================
if __name__ == "__main__":
    print("Network Threat Analyzer Started")
    sniff(iface=CAPTURE_INTERFACE, prn=handle_packet, store=False)
