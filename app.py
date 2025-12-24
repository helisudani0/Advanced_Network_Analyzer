import threading
import time
import socket
from scapy.all import sniff, IP, TCP, DNS
from collections import defaultdict, deque
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

# ===================== CONFIG =====================
CAPTURE_INTERFACE = None
SCORE_DECAY = 3
DECAY_INTERVAL = 15
ALERT_THRESHOLD_MED = 10
ALERT_THRESHOLD_HIGH = 20
ALERT_COOLDOWN = 60
MAX_SCORE = 100

# ===================== HOST STATE =====================
hosts = defaultdict(lambda: {
    "dns": deque(maxlen=100),
    "http": deque(maxlen=100),
    "score": 0,
    "last_decay": time.time(),
    "severity": "LOW",
    "last_alert": 0
})

# ===================== GUI SETUP =====================
root = tk.Tk()
root.title("Network Threat Analyzer")
root.geometry("1100x600")
root.configure(bg="#0f172a")

style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
    background="#020617",
    foreground="white",
    rowheight=22,
    fieldbackground="#020617"
)
style.map("Treeview", background=[("selected", "#2563eb")])

# ===================== PANELS =====================
top_frame = tk.Frame(root, bg="#020617")
top_frame.pack(fill=tk.BOTH, expand=True)

bottom_frame = tk.Frame(root, bg="#020617", height=200)
bottom_frame.pack(fill=tk.X)

# ---- Live Events ----
events_box = ScrolledText(top_frame, bg="#020617", fg="white",
                          font=("Consolas", 10), width=70)
events_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# ---- Alerts ----
alerts_box = ScrolledText(top_frame, bg="#020617", fg="white",
                          font=("Consolas", 10), width=50)
alerts_box.pack(side=tk.RIGHT, fill=tk.BOTH)

# ---- Host Table ----
columns = ("IP", "Score", "Severity", "DNS", "HTTP")
host_table = ttk.Treeview(bottom_frame, columns=columns, show="headings")

for col in columns:
    host_table.heading(col, text=col)
    host_table.column(col, anchor="center")

host_table.pack(fill=tk.BOTH, expand=True)

# ===================== GUI HELPERS =====================
def log_event(msg, color="white"):
    events_box.insert(tk.END, msg + "\n", color)
    events_box.tag_config(color, foreground=color)
    events_box.see(tk.END)

def log_alert(msg, color):
    alerts_box.insert(tk.END, msg + "\n", color)
    alerts_box.tag_config(color, foreground=color)
    alerts_box.see(tk.END)

def refresh_hosts():
    host_table.delete(*host_table.get_children())
    for ip, h in hosts.items():
        host_table.insert("", tk.END, values=(
            ip, h["score"], h["severity"],
            len(h["dns"]), len(h["http"])
        ))
    root.after(3000, refresh_hosts)

# ===================== UTIL =====================
def resolve_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

# ===================== NORMALIZATION =====================
def normalize(packet):
    if not packet.haslayer(IP):
        return None

    if packet.haslayer(DNS) and packet[DNS].qd:
        return ("DNS", packet[IP].src,
                packet[DNS].qd.qname.decode(errors="ignore"))

    if packet.haslayer(TCP) and packet[TCP].dport in [80, 443]:
        return ("HTTP", packet[IP].src,
                resolve_ip(packet[IP].dst))

    return None

# ===================== DETECTION =====================
def correlate(event):
    etype, src, detail = event
    host = hosts[src]

    if etype == "DNS":
        host["dns"].append(detail)
        if detail.endswith(".in-addr.arpa."):
            host["score"] += 1
        elif len(detail) > 50:
            host["score"] += 2

    elif etype == "HTTP":
        host["http"].append(detail)
        if not any(x in detail for x in [
            "google", "akamai", "amazonaws",
            "cloudfront", "windowsupdate"
        ]):
            host["score"] += 1

    host["score"] = min(MAX_SCORE, host["score"])
    decay(src)
    evaluate(src)

def decay(ip):
    host = hosts[ip]
    now = time.time()
    if now - host["last_decay"] >= DECAY_INTERVAL:
        host["score"] = max(0, host["score"] - SCORE_DECAY)
        host["last_decay"] = now

def evaluate(ip):
    host = hosts[ip]
    now = time.time()

    if host["score"] >= ALERT_THRESHOLD_HIGH:
        sev = "HIGH"
    elif host["score"] >= ALERT_THRESHOLD_MED:
        sev = "MEDIUM"
    else:
        sev = "LOW"

    if rank(sev) > rank(host["severity"]):
        if now - host["last_alert"] >= ALERT_COOLDOWN:
            raise_alert(ip, sev)
            host["severity"] = sev
            host["last_alert"] = now

def rank(s):
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2}[s]

# ===================== ALERT =====================
def raise_alert(ip, level):
    color = "orange" if level == "MEDIUM" else "red"
    h = hosts[ip]

    log_alert("="*55, color)
    log_alert(f" {level} ALERT", color)
    log_alert(f"Host: {ip}", color)
    log_alert(f"Score: {h['score']}", color)
    log_alert(f"DNS: {len(h['dns'])} | HTTP: {len(h['http'])}", color)
    log_alert("Verdict: Monitoring", color)
    log_alert("="*55 + "\n", color)

# ===================== PACKET HANDLER =====================
def handle(packet):
    event = normalize(packet)
    if not event:
        return

    etype, src, detail = event
    correlate(event)

    if etype == "DNS":
        log_event(f"DNS  {src} → {detail}", "cyan")
    else:
        log_event(f"HTTP {src} → {detail}", "lightgreen")

# ===================== THREAD =====================
def sniff_thread():
    sniff(iface=CAPTURE_INTERFACE, prn=handle, store=False)

threading.Thread(target=sniff_thread, daemon=True).start()

log_event("SOC Dashboard Started", "yellow")
log_event("Listening for traffic...\n", "yellow")

refresh_hosts()
root.mainloop()
