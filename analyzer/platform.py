from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
import ipaddress
import math
import os
import queue
import re
import socket
import statistics
import threading
import time
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from .config import PlatformConfig
from .intel import ThreatIntelManager, normalize_domain
from .models import AlertRecord, DetectionFinding, HostSnapshot, PacketContext, SessionRecord
from .output import AlertRouter
from .reporting import ReportGenerator
from .storage import SQLiteStore

try:
    from geoip2.database import Reader as GeoIPReader
except Exception:
    GeoIPReader = None

try:
    from scapy.all import DNS, IP, IPv6, PcapReader, Raw, TCP, UDP, sniff
    SCAPY_IMPORT_ERROR = None
except Exception as exc:
    DNS = None
    IP = None
    IPv6 = None
    PcapReader = None
    Raw = None
    TCP = None
    UDP = None
    sniff = None
    SCAPY_IMPORT_ERROR = exc

try:
    from cryptography import x509
except Exception:
    x509 = None

try:
    from sklearn.ensemble import IsolationForest
except Exception:
    IsolationForest = None


HTTP_PORTS = {80, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443, 9443}
DNS_PORTS = {53}
MDNS_PORT = 5353
MDNS_GROUPS = {"224.0.0.251", "ff02::fb"}
IRC_PORTS = {6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6697}
P2P_PORTS = {6881, 6882, 6883, 6884, 6885, 51413}
SMB_PORTS = {139, 445}
RDP_PORTS = {3389}
LDAP_PORTS = {389, 636}
KERBEROS_PORTS = {88}
TLS_VERSION_MAP = {
    0x0300: "SSLv3",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SUSPICIOUS_USER_AGENTS = (
    "curl",
    "wget",
    "python-requests",
    "powershell",
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "go-http-client",
    "libwww",
    "java/",
)
TRUSTED_HOST_KEYWORDS = (
    "google",
    "gstatic",
    "akamai",
    "amazonaws",
    "cloudfront",
    "microsoft",
    "windowsupdate",
    "office365",
    "github",
    "fastly",
    "cloudflare",
    "apple",
)
SUSPICIOUS_CERT_KEYWORDS = ("localhost", "test", "default", "internet widgits", "snakeoil")
SQLI_PATTERNS = (
    "union select",
    "' or 1=1",
    "\" or 1=1",
    "drop table",
    "information_schema",
    "sleep(",
    "benchmark(",
    "or 1=1--",
)
DIRECTORY_TRAVERSAL_PATTERNS = ("../", "..%2f", "%2e%2e/", "..\\")
BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{80,}={0,2})")
FILE_HINT_RE = re.compile(r"/[^?\s]+\.(zip|7z|rar|exe|dll|pdf|docx?|xlsx?|pptx?)", re.IGNORECASE)


@dataclass
class HostState:
    snapshot: HostSnapshot
    last_decay: float = field(default_factory=time.time)
    packet_times: Deque[float] = field(default_factory=lambda: deque(maxlen=4096))
    dns_times: Deque[float] = field(default_factory=lambda: deque(maxlen=2048))
    syn_times: Deque[float] = field(default_factory=lambda: deque(maxlen=2048))
    outbound_bytes: Deque[Tuple[float, int]] = field(default_factory=lambda: deque(maxlen=4096))
    outbound_dest_bytes: Dict[str, Deque[Tuple[float, int]]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=2048))
    )
    dns_domains: Dict[str, Deque[Tuple[float, str, float]]] = field(
        default_factory=lambda: defaultdict(lambda: deque(maxlen=512))
    )
    destination_counts: Counter = field(default_factory=Counter)
    protocol_counts: Counter = field(default_factory=Counter)
    port_counts: Counter = field(default_factory=Counter)
    recent_findings: Deque[str] = field(default_factory=lambda: deque(maxlen=12))
    rule_cooldowns: Dict[str, float] = field(default_factory=dict)
    baseline_destinations: Counter = field(default_factory=Counter)
    baseline_ports: Counter = field(default_factory=Counter)
    baseline_protocols: Counter = field(default_factory=Counter)
    feature_samples: Deque[List[float]] = field(default_factory=lambda: deque(maxlen=512))
    interarrival_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=256))
    last_packet_time: float = 0.0
    last_seen: float = field(default_factory=time.time)


@dataclass
class FlowState:
    times: Deque[float] = field(default_factory=lambda: deque(maxlen=16))
    last_seen: float = 0.0
    last_sni: str = ""
    server_names: List[str] = field(default_factory=list)


def safe_decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    return str(value or "")


def base_domain(value: str) -> str:
    normalized = normalize_domain(value)
    parts = [part for part in normalized.split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return parts[0] if parts else ""


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def is_private_or_local(ip_value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
    )


def infer_direction(src_ip: str, dst_ip: str) -> str:
    src_local = is_private_or_local(src_ip)
    dst_local = is_private_or_local(dst_ip)
    if src_local and not dst_local:
        return "outbound"
    if not src_local and dst_local:
        return "inbound"
    if src_local and dst_local:
        return "internal"
    return "external"


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def trim_time_window(items: Deque[float], now: float, window: float) -> None:
    while items and now - items[0] > window:
        items.popleft()


def trim_tuple_window(items: Deque[Tuple[float, int]], now: float, window: float) -> None:
    while items and now - items[0][0] > window:
        items.popleft()


def sum_bytes(items: Iterable[Tuple[float, int]]) -> int:
    return sum(size for _, size in items)


def fingerprint_os(ttl: int, tcp_window: int) -> str:
    if ttl >= 200:
        return "Network appliance / embedded"
    if ttl >= 120:
        if tcp_window in {64240, 65535, 8192}:
            return "Windows"
        return "Windows-like"
    if ttl >= 60:
        if tcp_window in {29200, 5840, 5720, 65535}:
            return "Linux / Unix"
        return "Linux-like"
    if ttl > 0:
        return "Low-TTL device"
    return "Unknown"


def transport_code(transport: str) -> int:
    mapping = {"TCP": 1, "UDP": 2, "DNS": 3, "HTTP": 4, "HTTPS": 5, "TLS": 6}
    return mapping.get(transport, 0)


def normalize_session_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, transport: str) -> str:
    endpoints = [(src_ip, src_port), (dst_ip, dst_port)]
    left, right = sorted(endpoints)
    return f"{left[0]}:{left[1]}-{right[0]}:{right[1]}-{transport}"


def wildcard_match(name: str, pattern: str) -> bool:
    name = normalize_domain(name)
    pattern = normalize_domain(pattern)
    if not name or not pattern:
        return False
    if pattern.startswith("*."):
        return name.endswith(pattern[1:]) and name.count(".") >= pattern.count(".")
    return name == pattern


def parse_http_payload(payload: bytes) -> Dict[str, object]:
    if not payload:
        return {}
    text = payload[:4096].decode("utf-8", errors="ignore")
    lines = text.splitlines()
    if not lines:
        return {}

    first_line = lines[0].strip()
    response = first_line.startswith("HTTP/")
    headers: Dict[str, str] = {}
    body = ""
    separator = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
    if separator in text:
        _, body = text.split(separator, 1)

    for line in lines[1:50]:
        if not line.strip():
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    if response:
        return {
            "is_http": True,
            "is_response": True,
            "status": first_line,
            "headers": headers,
            "body_size": len(body.encode("utf-8", errors="ignore")),
            "body_preview": body[:512],
        }

    parts = first_line.split()
    method = parts[0].upper() if parts else ""
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}:
        return {}
    url = parts[1] if len(parts) > 1 else "/"
    host = headers.get("host", "")
    query_string = url.split("?", 1)[1] if "?" in url else ""
    return {
        "is_http": True,
        "is_response": False,
        "method": method,
        "url": url,
        "host": host,
        "user_agent": headers.get("user-agent", ""),
        "headers": headers,
        "query_string": query_string,
        "body_size": len(body.encode("utf-8", errors="ignore")),
        "body_preview": body[:1024],
    }


def parse_tls_client_hello(payload: bytes) -> Dict[str, object]:
    if len(payload) < 11 or payload[0] != 0x16 or payload[5] != 0x01:
        return {}
    version = int.from_bytes(payload[9:11], "big")
    pointer = 11 + 32
    if pointer >= len(payload):
        return {"version": TLS_VERSION_MAP.get(version, hex(version))}

    session_id_len = payload[pointer]
    pointer += 1 + session_id_len
    if pointer + 2 > len(payload):
        return {"version": TLS_VERSION_MAP.get(version, hex(version))}
    cipher_len = int.from_bytes(payload[pointer:pointer + 2], "big")
    pointer += 2 + cipher_len
    if pointer >= len(payload):
        return {"version": TLS_VERSION_MAP.get(version, hex(version))}
    compression_len = payload[pointer]
    pointer += 1 + compression_len
    if pointer + 2 > len(payload):
        return {"version": TLS_VERSION_MAP.get(version, hex(version))}
    extensions_len = int.from_bytes(payload[pointer:pointer + 2], "big")
    pointer += 2
    end = min(len(payload), pointer + extensions_len)
    sni = ""

    while pointer + 4 <= end:
        ext_type = int.from_bytes(payload[pointer:pointer + 2], "big")
        ext_len = int.from_bytes(payload[pointer + 2:pointer + 4], "big")
        pointer += 4
        ext_data = payload[pointer:pointer + ext_len]
        if ext_type == 0 and len(ext_data) >= 5:
            names_len = int.from_bytes(ext_data[0:2], "big")
            cursor = 2
            while cursor + 3 <= min(len(ext_data), 2 + names_len):
                name_type = ext_data[cursor]
                name_len = int.from_bytes(ext_data[cursor + 1:cursor + 3], "big")
                cursor += 3
                if name_type == 0 and cursor + name_len <= len(ext_data):
                    sni = normalize_domain(ext_data[cursor:cursor + name_len].decode("utf-8", errors="ignore"))
                    break
                cursor += name_len
        pointer += ext_len

    return {"version": TLS_VERSION_MAP.get(version, hex(version)), "sni": sni}


def parse_tls_certificate(payload: bytes) -> Dict[str, object]:
    if x509 is None or len(payload) < 15 or payload[0] != 0x16 or payload[5] != 0x0B:
        return {}
    try:
        pointer = 9
        cert_list_len = int.from_bytes(payload[pointer:pointer + 3], "big")
        pointer += 3
        if cert_list_len <= 0 or pointer + 3 > len(payload):
            return {}
        cert_len = int.from_bytes(payload[pointer:pointer + 3], "big")
        pointer += 3
        der = payload[pointer:pointer + cert_len]
        if len(der) != cert_len:
            return {}
        cert = x509.load_der_x509_certificate(der)
        names: List[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = [normalize_domain(name) for name in san.value.get_values_for_type(x509.DNSName)]
        except Exception:
            names = []
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        common_names = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if common_names:
            names.append(normalize_domain(common_names[0].value))
        return {
            "subject": subject,
            "issuer": issuer,
            "names": [name for name in names if name],
            "self_signed": subject == issuer,
        }
    except Exception:
        return {}


class GeoIPResolver:
    def __init__(self, database_path: str):
        self.database_path = database_path or os.getenv("GEOIP_DB", "")
        self.reader = None
        self.cache: Dict[str, str] = {}
        self.status = "GeoIP disabled"
        if not self.database_path:
            self.status = "GeoIP disabled (no database configured)"
            return
        if GeoIPReader is None:
            self.status = "GeoIP disabled (geoip2 not installed)"
            return
        try:
            self.reader = GeoIPReader(self.database_path)
            self.status = f"GeoIP enabled using {self.database_path}"
        except Exception as exc:
            self.status = f"GeoIP disabled ({exc})"

    def lookup(self, ip_value: str) -> str:
        if ip_value in self.cache:
            return self.cache[ip_value]
        if is_private_or_local(ip_value):
            self.cache[ip_value] = "Private/Local"
            return self.cache[ip_value]
        if self.reader is None:
            self.cache[ip_value] = "GeoIP unavailable"
            return self.cache[ip_value]
        try:
            record = self.reader.city(ip_value)
            country = record.country.iso_code or record.country.name or "Unknown"
            city = record.city.name or ""
            value = country if not city else f"{country} / {city}"
        except Exception:
            value = "Unknown"
        self.cache[ip_value] = value
        return value


class ThreatPlatform:
    def __init__(self, config: PlatformConfig):
        self.config = config
        self.config.ensure_directories()
        self.store = SQLiteStore(config.database_path)
        self.router = AlertRouter(config)
        self.intel = ThreatIntelManager(config.ioc_sources)
        self.intel.load_all()
        self.geoip = GeoIPResolver(config.geoip_db)
        self.hosts: Dict[str, HostState] = {}
        self.flows: Dict[Tuple[str, str, int, str], FlowState] = defaultdict(FlowState)
        self.sessions: Dict[str, SessionRecord] = {}
        self.tls_client_hello: Dict[str, Dict[str, object]] = {}
        self.horizontal_scans: Dict[str, Dict[str, Deque[Tuple[float, int]]]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=512))
        )
        self.vertical_scans: Dict[str, Dict[int, Deque[Tuple[float, str]]]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=512))
        )
        self.packet_queue: "queue.Queue[Tuple[object, Optional[float]]]" = queue.Queue(maxsize=config.max_queue_size)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.capture_threads: List[threading.Thread] = []
        self.worker_threads: List[threading.Thread] = []
        self.hostname_cache: Dict[str, str] = {}
        self.alert_count = 0
        self.packet_count = 0
        self.ml_model = None
        self.ml_features: Deque[List[float]] = deque(maxlen=2048)
        self.ml_last_train_count = 0

    def start_workers(self) -> None:
        if self.worker_threads:
            return
        for index in range(max(1, self.config.worker_count)):
            thread = threading.Thread(target=self._worker_loop, name=f"worker-{index}", daemon=True)
            thread.start()
            self.worker_threads.append(thread)

    def stop(self) -> None:
        self.stop_event.set()
        if self.config.save_reports_on_exit:
            self.generate_reports()
        self.store.close()

    def snapshot_hosts(self) -> List[HostSnapshot]:
        with self.lock:
            rows = [state.snapshot for state in self.hosts.values()]
        return sorted(rows, key=lambda row: (-row.score, -row.packet_count, row.ip))

    def summary(self) -> Dict[str, object]:
        return {
            "packets_processed": self.packet_count,
            "alerts_generated": self.alert_count,
            "geoip_status": self.geoip.status,
            "tracked_hosts": len(self.hosts),
            "tracked_sessions": len(self.sessions),
            "ioc_count": len(self.intel.ip_feeds) + len(self.intel.domain_feeds),
        }

    def export_iocs(self, path: str) -> str:
        alerts = self.store.fetch_alerts(limit=1000)
        values = set()
        for alert in alerts:
            for indicator in alert.get("iocs", []):
                values.add(indicator)
        output = Path(path)
        output.write_text("\n".join(sorted(values)), encoding="utf-8")
        return str(output)

    def generate_reports(self) -> Dict[str, str]:
        generator = ReportGenerator(self.store, self.config.report_dir)
        return generator.generate(self.summary(), self.snapshot_hosts())

    def replay_pcap(self, pcap_path: str, playback_speed: Optional[float] = None) -> None:
        if PcapReader is None:
            raise RuntimeError(f"Scapy is required for PCAP playback: {SCAPY_IMPORT_ERROR}")
        file_path = Path(pcap_path)
        if not file_path.exists():
            raise FileNotFoundError(file_path)
        self.start_workers()
        previous = None
        speed = self.config.playback_speed if playback_speed is None else playback_speed
        with PcapReader(str(file_path)) as reader:
            for packet in reader:
                packet_time = float(getattr(packet, "time", time.time()))
                if speed and previous is not None:
                    wait = max(0.0, packet_time - previous) / max(speed, 0.0001)
                    if wait:
                        time.sleep(min(wait, 1.5))
                self.enqueue_packet(packet, packet_time)
                previous = packet_time
        self.packet_queue.join()

    def start_live_capture(self) -> None:
        if sniff is None:
            raise RuntimeError(f"Scapy is required for live capture: {SCAPY_IMPORT_ERROR}")
        self.start_workers()
        interfaces = self.config.interfaces or [None]
        for iface in interfaces:
            thread = threading.Thread(
                target=self._sniff_interface,
                args=(iface,),
                daemon=True,
                name=f"sniff-{iface or 'default'}",
            )
            thread.start()
            self.capture_threads.append(thread)

    def enqueue_packet(self, packet, packet_time: Optional[float] = None) -> None:
        try:
            self.packet_queue.put((packet, packet_time), timeout=2)
        except queue.Full:
            return

    def _worker_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                packet, packet_time = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.process_packet(packet, packet_time)
            finally:
                self.packet_queue.task_done()

    def _sniff_interface(self, iface: Optional[str]) -> None:
        sniff(
            iface=iface,
            store=False,
            filter=self.config.bpf_filter or None,
            prn=lambda packet: self.enqueue_packet(packet),
        )

    def resolve_hostname(self, ip_value: str) -> str:
        cached = self.hostname_cache.get(ip_value)
        if cached:
            return cached
        try:
            value = socket.gethostbyaddr(ip_value)[0].lower()
        except Exception:
            value = ip_value
        self.hostname_cache[ip_value] = value
        return value

    def get_host_state(self, ip_value: str) -> HostState:
        state = self.hosts.get(ip_value)
        if state is None:
            state = HostState(snapshot=HostSnapshot(ip=ip_value))
            self.hosts[ip_value] = state
        return state

    def process_packet(self, packet, packet_time: Optional[float] = None) -> None:
        context = self.build_context(packet, packet_time)
        if context is None or not self._allow_context(context):
            return

        with self.lock:
            self.packet_count += 1
            state = self.get_host_state(context.src_ip)
            self._decay_score(state, context.timestamp)
            self._update_state(state, context)
            self._update_session(context, packet)
            self._update_reputation(context, state)
            self.store.insert_event(context)
            self.store.upsert_session(self.sessions[context.session_id])

            findings: List[DetectionFinding] = []
            findings.extend(self._detect_ioc_matches(context))
            findings.extend(self._detect_dns_tunneling(state, context))
            findings.extend(self._detect_port_scans(context))
            findings.extend(self._detect_tls_anomalies(context))
            findings.extend(self._detect_rc_p2p(context))
            findings.extend(self._detect_http_anomalies(context))
            findings.extend(self._detect_beaconing(context))
            findings.extend(self._detect_exfiltration(state, context))
            findings.extend(self._detect_baseline_deviation(state, context))
            findings.extend(self._detect_ml_anomaly(state, context))
            findings.extend(self._detect_protocol_activity(context))

            self._apply_findings(state, context, findings)
            self._persist_baseline_if_needed(state, context.timestamp)

    def build_context(self, packet, packet_time: Optional[float] = None) -> Optional[PacketContext]:
        if IP is None:
            return None
        ip_layer = None
        if IP is not None and packet.haslayer(IP):
            ip_layer = packet[IP]
        elif IPv6 is not None and packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
        if ip_layer is None:
            return None

        timestamp = float(packet_time if packet_time is not None else getattr(packet, "time", time.time()))
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        transport = "IP"
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        tcp_window = 0
        payload = b""
        ttl = int(getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", 0)) or 0)

        if TCP is not None and packet.haslayer(TCP):
            transport = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            tcp_flags = int(packet[TCP].flags)
            tcp_window = int(packet[TCP].window)
        elif UDP is not None and packet.haslayer(UDP):
            transport = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        if Raw is not None and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load[:8192])

        direction = infer_direction(src_ip, dst_ip)
        private_pair = is_private_or_local(src_ip) and is_private_or_local(dst_ip)
        category = transport
        detail = f"{src_port}->{dst_port}"
        hostname = self.resolve_hostname(dst_ip) if direction == "outbound" and not is_private_or_local(dst_ip) else dst_ip
        domain = base_domain(hostname)
        geo = self.geoip.lookup(dst_ip)
        os_guess = fingerprint_os(ttl, tcp_window)
        payload_preview = safe_decode(payload[:512]).replace("\r", " ").replace("\n", " ")[:300]
        protocol_tags: List[str] = []
        dns_query = ""
        http_method = ""
        http_url = ""
        http_host = ""
        http_user_agent = ""
        http_body_size = 0
        http_query_string = ""
        tls_version = ""
        tls_sni = ""
        tls_cert_subject = ""
        tls_cert_issuer = ""
        tls_self_signed = False

        if DNS is not None and packet.haslayer(DNS) and getattr(packet[DNS], "qd", None):
            dns_query = normalize_domain(packet[DNS].qd.qname.decode(errors="ignore"))
            hostname = base_domain(dns_query) or hostname
            domain = base_domain(dns_query)
            detail = dns_query
            category = "mDNS" if dst_port == MDNS_PORT or src_port == MDNS_PORT or dst_ip.lower() in MDNS_GROUPS else "DNS"

        http_info = parse_http_payload(payload)
        if http_info.get("is_http"):
            if http_info.get("is_response"):
                category = "HTTP"
                protocol_tags.append("http-response")
            else:
                category = "HTTP" if dst_port not in HTTPS_PORTS else "HTTPS"
                http_method = str(http_info.get("method", ""))
                http_url = str(http_info.get("url", ""))
                http_host = str(http_info.get("host", "")) or hostname
                http_user_agent = str(http_info.get("user_agent", ""))
                http_body_size = int(http_info.get("body_size", 0))
                http_query_string = str(http_info.get("query_string", ""))
                hostname = http_host or hostname
                domain = base_domain(hostname)
                detail = http_url or hostname

        tls_hello = parse_tls_client_hello(payload)
        if tls_hello:
            tls_version = str(tls_hello.get("version", ""))
            tls_sni = str(tls_hello.get("sni", ""))
            if tls_sni:
                hostname = tls_sni
                domain = base_domain(tls_sni)
            category = "TLS"
            detail = tls_sni or detail
            client_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            self.tls_client_hello[client_key] = tls_hello

        cert_info = parse_tls_certificate(payload)
        if cert_info:
            tls_cert_subject = str(cert_info.get("subject", ""))
            tls_cert_issuer = str(cert_info.get("issuer", ""))
            tls_self_signed = bool(cert_info.get("self_signed", False))
            category = "TLS"
            reverse_key = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
            hello = self.tls_client_hello.get(reverse_key, {})
            if hello and hello.get("sni"):
                tls_sni = str(hello["sni"])
                hostname = tls_sni
                domain = base_domain(tls_sni)

        if transport == "TCP" and payload:
            text_preview = payload_preview.upper()
            if any(marker in text_preview for marker in ["NICK ", "USER ", "PRIVMSG", "JOIN #"]):
                protocol_tags.append("irc")
                category = "IRC"
                detail = payload_preview
            if "BITTORRENT PROTOCOL" in text_preview or "INFO_HASH=" in text_preview or "PEER_ID=" in text_preview:
                protocol_tags.append("bittorrent")
                category = "P2P"
                detail = payload_preview

        if dst_port in P2P_PORTS or src_port in P2P_PORTS:
            protocol_tags.append("p2p-port")
        if dst_port in SMB_PORTS or src_port in SMB_PORTS:
            protocol_tags.append("smb")
            if category == "TCP":
                category = "SMB"
        if dst_port in RDP_PORTS or src_port in RDP_PORTS:
            protocol_tags.append("rdp")
            if category == "TCP":
                category = "RDP"
        if dst_port in LDAP_PORTS or src_port in LDAP_PORTS:
            protocol_tags.append("ldap")
            if category == "TCP":
                category = "LDAP"
        if dst_port in KERBEROS_PORTS or src_port in KERBEROS_PORTS:
            protocol_tags.append("kerberos")
            if category in {"UDP", "TCP"}:
                category = "KERBEROS"

        session_id = normalize_session_id(src_ip, src_port, dst_ip, dst_port, transport)
        trusted = any(keyword in hostname.lower() for keyword in TRUSTED_HOST_KEYWORDS) or private_pair
        ioc_matches = self.intel.match(
            [src_ip, dst_ip],
            [hostname, domain, dns_query],
        )

        context = PacketContext(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            category=category,
            detail=detail,
            packet_len=len(packet),
            direction=direction,
            hostname=hostname,
            base_domain=domain,
            geo=geo,
            trusted=trusted,
            private_pair=private_pair,
            dns_query=dns_query,
            http_method=http_method,
            http_url=http_url,
            http_host=http_host,
            http_user_agent=http_user_agent,
            http_body_size=http_body_size,
            http_query_string=http_query_string,
            tls_version=tls_version,
            tls_sni=tls_sni,
            tls_cert_subject=tls_cert_subject,
            tls_cert_issuer=tls_cert_issuer,
            tls_self_signed=tls_self_signed,
            payload_preview=payload_preview,
            os_guess=os_guess,
            ttl=ttl,
            tcp_window=tcp_window,
            tcp_flags=tcp_flags,
            session_id=session_id,
            protocol_tags=protocol_tags,
            ioc_matches=ioc_matches,
        )
        return context

    def _allow_context(self, context: PacketContext) -> bool:
        quick = self.config.quick_filter.lower()
        if quick == "http" and context.category not in {"HTTP", "HTTPS"}:
            return False
        if quick == "dns" and context.category not in {"DNS", "mDNS"}:
            return False
        if quick == "external" and context.private_pair:
            return False
        return True

    def _decay_score(self, state: HostState, now: float) -> None:
        if now - state.last_decay < 30:
            return
        intervals = int((now - state.last_decay) // 30)
        if intervals <= 0:
            return
        state.snapshot.score = max(0, state.snapshot.score - (intervals * 2))
        state.last_decay += intervals * 30
        state.snapshot.severity = self._severity_from_score(state.snapshot.score)

    def _update_state(self, state: HostState, context: PacketContext) -> None:
        state.last_seen = context.timestamp
        state.snapshot.packet_count += 1
        state.snapshot.os_guess = context.os_guess or state.snapshot.os_guess
        state.snapshot.outbound_bytes += context.packet_len if context.direction == "outbound" else 0
        state.snapshot.top_destination = context.hostname or context.dst_ip
        state.packet_times.append(context.timestamp)
        trim_time_window(state.packet_times, context.timestamp, 30)
        state.protocol_counts[context.category] += 1
        state.port_counts[context.dst_port] += 1
        state.destination_counts[context.hostname or context.dst_ip] += 1

        if context.category in {"DNS", "mDNS"}:
            state.snapshot.dns_count += 1
            state.dns_times.append(context.timestamp)
            trim_time_window(state.dns_times, context.timestamp, self.config.dns_frequency_window)
        if context.category in {"HTTP", "HTTPS"}:
            state.snapshot.http_count += 1
        if context.category == "TLS":
            state.snapshot.tls_count += 1
        if context.transport == "TCP" and context.tcp_flags & 0x02 and not context.tcp_flags & 0x10:
            state.syn_times.append(context.timestamp)
            trim_time_window(state.syn_times, context.timestamp, self.config.portscan_window)

        if context.direction == "outbound" and not is_private_or_local(context.dst_ip):
            state.outbound_bytes.append((context.timestamp, context.packet_len))
            trim_tuple_window(state.outbound_bytes, context.timestamp, self.config.exfil_window)
            state.outbound_dest_bytes[context.dst_ip].append((context.timestamp, context.packet_len))
            trim_tuple_window(
                state.outbound_dest_bytes[context.dst_ip],
                context.timestamp,
                self.config.exfil_window,
            )

        state.baseline_destinations[context.hostname or context.dst_ip] += 1
        state.baseline_ports[context.dst_port] += 1
        state.baseline_protocols[context.category] += 1
        state.snapshot.baseline_ready = state.snapshot.packet_count >= self.config.baseline_min_events
        if state.last_packet_time:
            delta = max(0.0, context.timestamp - state.last_packet_time)
            state.interarrival_samples.append(delta)
        state.last_packet_time = context.timestamp

        feature_vector = [
            float(context.packet_len),
            float(context.dst_port),
            float(transport_code(context.category)),
            float(context.ttl or 0),
            float(context.http_body_size or 0),
        ]
        state.feature_samples.append(feature_vector)
        self.ml_features.append(feature_vector)

    def _update_session(self, context: PacketContext, packet) -> None:
        session = self.sessions.get(context.session_id)
        if session is None:
            session = SessionRecord(
                session_id=context.session_id,
                src_ip=context.src_ip,
                dst_ip=context.dst_ip,
                src_port=context.src_port,
                dst_port=context.dst_port,
                transport=context.transport,
                first_seen=context.timestamp,
                last_seen=context.timestamp,
            )
            self.sessions[context.session_id] = session
        session.last_seen = context.timestamp
        session.packet_count += 1
        session.total_bytes += context.packet_len
        if context.category not in session.protocol_hints:
            session.protocol_hints.append(context.category)
        if context.payload_preview and len(session.snippets) < 20:
            session.snippets.append(context.payload_preview)

        if context.http_url and FILE_HINT_RE.search(context.http_url):
            self._extract_http_artifact(context)
            session.extracted_artifact = context.http_url

    def _extract_http_artifact(self, context: PacketContext) -> None:
        artifact_dir = Path(self.config.artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        safe_name = context.session_id.replace(":", "_").replace("/", "_")
        artifact_path = artifact_dir / f"{safe_name}.txt"
        if artifact_path.exists():
            return
        artifact_path.write_text(
            f"Potential file transfer observed\nHost: {context.src_ip}\nDestination: {context.dst_ip}\nURL: {context.http_url}\n",
            encoding="utf-8",
        )

    def _update_reputation(self, context: PacketContext, state: HostState) -> None:
        risk = 0
        factors: List[str] = []
        if context.ioc_matches:
            risk += 40
            factors.append("matched threat intelligence feed")
        if any(context.geo.startswith(country) for country in self.config.high_risk_countries):
            risk += 10
            factors.append(f"destination GeoIP {context.geo} is high risk for the profile")
        if context.dst_port not in HTTP_PORTS | HTTPS_PORTS | DNS_PORTS | IRC_PORTS | P2P_PORTS | SMB_PORTS | RDP_PORTS | LDAP_PORTS | KERBEROS_PORTS:
            risk += 5
            factors.append("non-standard destination port")
        if context.direction == "outbound" and state.snapshot.outbound_bytes > self.config.exfil_bytes_medium:
            risk += 8
            factors.append("high outbound volume")
        if context.tls_version in {"SSLv3", "TLS1.0"}:
            risk += 8
            factors.append("outdated TLS version")
        context.risk_score = risk
        context.risk_factors = factors
        state.snapshot.reputation_score = max(state.snapshot.reputation_score, risk)

    def _detect_ioc_matches(self, context: PacketContext) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        for match in context.ioc_matches:
            severity = "CRITICAL" if match.confidence >= 85 else "HIGH"
            findings.append(
                DetectionFinding(
                    title="Threat intelligence IOC match",
                    severity=severity,
                    classification="Threat intelligence",
                    score_delta=15 if severity == "CRITICAL" else 10,
                    reasons=[
                        f"Observed indicator {match.value} matched a {match.source} feed entry.",
                        match.description or "Feed match occurred in real time against the observed traffic.",
                    ],
                    action="Block the IOC, investigate related processes, and pivot through historical alerts for the same indicator.",
                    mitre_technique="T1583",
                    mitre_tactic="Resource Development",
                    dedupe_key=f"ioc:{match.indicator_type}:{match.value}",
                    iocs=[match.value],
                    auto_block=True,
                    cooldown=self.config.alert_cooldown,
                )
            )
        return findings

    def _detect_dns_tunneling(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        if context.category not in {"DNS", "mDNS"} or not context.dns_query:
            return []
        if context.category == "mDNS":
            if context.dst_ip.lower() not in MDNS_GROUPS:
                return [
                    DetectionFinding(
                        title="mDNS outside expected multicast range",
                        severity="MEDIUM",
                        classification="Protocol anomaly",
                        score_delta=4,
                        reasons=[
                            f"mDNS query {context.dns_query} targeted {context.dst_ip}:{context.dst_port}.",
                            "Legitimate mDNS should stay on multicast UDP/5353.",
                        ],
                        action="Inspect the sender for malformed discovery traffic or spoofed multicast behavior.",
                        mitre_technique="T1046",
                        mitre_tactic="Discovery",
                        dedupe_key=f"mdns:{context.src_ip}:{context.dst_ip}:{context.dst_port}",
                    )
                ]
            return []

        entropy = shannon_entropy(context.dns_query.replace(".", ""))
        history = state.dns_domains[context.base_domain or context.dns_query]
        history.append((context.timestamp, context.dns_query, entropy))
        while history and context.timestamp - history[0][0] > self.config.dns_frequency_window:
            history.popleft()

        unique_queries = {item[1] for item in history}
        high_entropy_queries = [item for item in history if item[2] >= self.config.dns_entropy_threshold]
        findings: List[DetectionFinding] = []
        if len(context.dns_query) > 50:
            findings.append(
                DetectionFinding(
                    title="Long DNS query",
                    severity="MEDIUM",
                    classification="DNS tunneling",
                    score_delta=4,
                    reasons=[
                        f"Query length was {len(context.dns_query)} characters.",
                        "Long labels can indicate data staging or tunneling.",
                    ],
                    action="Inspect the query string for encoded data and compare it with the host's normal resolver behavior.",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    dedupe_key=f"dns-long:{context.src_ip}:{context.base_domain}",
                )
            )
        if entropy >= self.config.dns_entropy_threshold and len(context.dns_query) >= 35:
            findings.append(
                DetectionFinding(
                    title="High-entropy DNS query",
                    severity="HIGH",
                    classification="DNS tunneling",
                    score_delta=6,
                    reasons=[
                        f"Query entropy measured {entropy:.2f}, which is consistent with encoded or randomized labels.",
                        f"Observed query: {context.dns_query}",
                    ],
                    action="Investigate for DNS tunneling, DGAs, or staged exfiltration through subdomains.",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    dedupe_key=f"dns-entropy:{context.src_ip}:{context.base_domain}",
                )
            )
        if len(history) >= self.config.dns_tunnel_query_threshold and len(unique_queries) >= max(10, self.config.dns_tunnel_query_threshold // 2):
            findings.append(
                DetectionFinding(
                    title="High-frequency DNS requests to a single domain",
                    severity="HIGH",
                    classification="DNS tunneling",
                    score_delta=7,
                    reasons=[
                        f"{len(history)} queries targeted {context.base_domain or context.dns_query} within {self.config.dns_frequency_window} seconds.",
                        f"{len(high_entropy_queries)} of those queries were high entropy.",
                    ],
                    action="Examine the queried domain, capture the traffic, and isolate the host if the pattern continues.",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    dedupe_key=f"dns-frequency:{context.src_ip}:{context.base_domain}",
                )
            )
        return findings

    def _detect_port_scans(self, context: PacketContext) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if context.transport != "TCP" or not (context.tcp_flags & 0x02):
            return findings

        horizontal = self.horizontal_scans[context.src_ip][context.dst_ip]
        horizontal.append((context.timestamp, context.dst_port))
        while horizontal and context.timestamp - horizontal[0][0] > self.config.portscan_window:
            horizontal.popleft()
        unique_ports = {port for _, port in horizontal}
        if len(unique_ports) >= self.config.horizontal_port_threshold:
            findings.append(
                DetectionFinding(
                    title="Horizontal port scan",
                    severity="HIGH",
                    classification="Reconnaissance",
                    score_delta=8,
                    reasons=[
                        f"{context.src_ip} touched {len(unique_ports)} ports on {context.dst_ip} within {self.config.portscan_window} seconds.",
                    ],
                    action="Block or isolate the scanner and review whether the target surface should be exposed.",
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    dedupe_key=f"horizontal-scan:{context.src_ip}:{context.dst_ip}",
                    aggregate_value=f"{len(unique_ports)} ports scanned in {self.config.portscan_window}s",
                )
            )

        vertical = self.vertical_scans[context.src_ip][context.dst_port]
        vertical.append((context.timestamp, context.dst_ip))
        while vertical and context.timestamp - vertical[0][0] > self.config.portscan_window:
            vertical.popleft()
        unique_hosts = {target for _, target in vertical}
        if len(unique_hosts) >= self.config.vertical_host_threshold:
            findings.append(
                DetectionFinding(
                    title="Vertical port scan",
                    severity="HIGH",
                    classification="Reconnaissance",
                    score_delta=8,
                    reasons=[
                        f"{context.src_ip} probed port {context.dst_port} on {len(unique_hosts)} hosts in {self.config.portscan_window} seconds.",
                    ],
                    action="Inspect the source for scanning tools and review the target subnet for exposure.",
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    dedupe_key=f"vertical-scan:{context.src_ip}:{context.dst_port}",
                    aggregate_value=f"{len(unique_hosts)} hosts probed on port {context.dst_port}",
                )
            )

        state = self.get_host_state(context.src_ip)
        trim_time_window(state.syn_times, context.timestamp, self.config.portscan_window)
        if len(state.syn_times) >= self.config.syn_scan_threshold:
            findings.append(
                DetectionFinding(
                    title="Half-open SYN scan or flood",
                    severity="HIGH",
                    classification="Reconnaissance",
                    score_delta=7,
                    reasons=[
                        f"{len(state.syn_times)} outbound SYN packets were observed from {context.src_ip} in {self.config.portscan_window} seconds.",
                        "This pattern is consistent with half-open scanning or SYN flood behavior.",
                    ],
                    action="Throttle or block the source and investigate for mass scanning or denial-of-service tooling.",
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    dedupe_key=f"syn-scan:{context.src_ip}",
                    aggregate_value=f"{len(state.syn_times)} SYN packets in {self.config.portscan_window}s",
                )
            )
        return findings

    def _detect_tls_anomalies(self, context: PacketContext) -> List[DetectionFinding]:
        if context.category != "TLS":
            return []
        findings: List[DetectionFinding] = []
        if context.tls_version in {"SSLv3", "TLS1.0", "TLS1.1"}:
            findings.append(
                DetectionFinding(
                    title="Outdated TLS or SSL version",
                    severity="MEDIUM",
                    classification="TLS anomaly",
                    score_delta=5,
                    reasons=[
                        f"Connection negotiated {context.tls_version}.",
                        "Legacy TLS versions are often seen in malware infrastructure and weak legacy systems.",
                    ],
                    action="Confirm whether the service is legacy and plan remediation or blocking if it is unapproved.",
                    mitre_technique="T1071",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"tls-version:{context.src_ip}:{context.dst_ip}:{context.tls_version}",
                )
            )
        if context.tls_self_signed:
            findings.append(
                DetectionFinding(
                    title="Self-signed TLS certificate",
                    severity="HIGH",
                    classification="TLS anomaly",
                    score_delta=7,
                    reasons=[
                        "A TLS certificate appeared self-signed in the observed handshake.",
                        context.tls_cert_subject or "Certificate subject metadata was present in the packet stream.",
                    ],
                    action="Validate whether the destination is an internal lab system or suspicious infrastructure.",
                    mitre_technique="T1583",
                    mitre_tactic="Resource Development",
                    dedupe_key=f"tls-self-signed:{context.dst_ip}:{context.tls_sni or context.hostname}",
                )
            )
        if context.tls_sni and context.tls_cert_subject:
            names = [normalize_domain(context.tls_sni)]
            certificate_names = []
            for value in re.findall(r"CN=([^,]+)", context.tls_cert_subject):
                certificate_names.append(normalize_domain(value))
            matched = any(
                wildcard_match(context.tls_sni, candidate) for candidate in certificate_names
            )
            if certificate_names and not matched:
                findings.append(
                    DetectionFinding(
                        title="TLS SNI and certificate mismatch",
                        severity="HIGH",
                        classification="TLS anomaly",
                        score_delta=8,
                        reasons=[
                            f"Client SNI was {context.tls_sni}, while the certificate subject was {context.tls_cert_subject}.",
                        ],
                        action="Inspect whether the destination is using a mismatched certificate, intercepting TLS, or fronting malicious infrastructure.",
                        mitre_technique="T1557",
                        mitre_tactic="Credential Access",
                        dedupe_key=f"tls-sni-mismatch:{context.dst_ip}:{context.tls_sni}",
                    )
                )
        if any(keyword in context.tls_cert_subject.lower() or keyword in context.tls_cert_issuer.lower() for keyword in SUSPICIOUS_CERT_KEYWORDS):
            findings.append(
                DetectionFinding(
                    title="Suspicious certificate metadata",
                    severity="MEDIUM",
                    classification="TLS anomaly",
                    score_delta=5,
                    reasons=[
                        f"Certificate metadata contained suspicious naming patterns: {context.tls_cert_subject or context.tls_cert_issuer}.",
                    ],
                    action="Review the destination's TLS certificate chain and ownership.",
                    mitre_technique="T1071",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"tls-cert-metadata:{context.dst_ip}:{context.tls_sni or context.hostname}",
                )
            )
        return findings

    def _detect_rc_p2p(self, context: PacketContext) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if "irc" in context.protocol_tags and context.dst_port not in IRC_PORTS:
            findings.append(
                DetectionFinding(
                    title="IRC command-and-control on non-standard port",
                    severity="HIGH",
                    classification="C2 protocol fingerprint",
                    score_delta=7,
                    reasons=[
                        f"IRC-like traffic was observed on TCP/{context.dst_port}.",
                        "Malware families often tunnel IRC C2 over random ports.",
                    ],
                    action="Inspect the payload and isolate the host if the conversation is unauthorized.",
                    mitre_technique="T1071",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"irc:{context.src_ip}:{context.dst_ip}:{context.dst_port}",
                )
            )
        if "bittorrent" in context.protocol_tags or "p2p-port" in context.protocol_tags:
            findings.append(
                DetectionFinding(
                    title="Peer-to-peer traffic pattern",
                    severity="MEDIUM",
                    classification="P2P protocol fingerprint",
                    score_delta=4,
                    reasons=[
                        f"BitTorrent or P2P characteristics were observed toward {context.dst_ip}:{context.dst_port}.",
                    ],
                    action="Confirm whether peer-to-peer traffic is permitted on this network and investigate if not.",
                    mitre_technique="T1095",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"p2p:{context.src_ip}:{context.dst_ip}:{context.dst_port}",
                )
            )
        return findings

    def _detect_http_anomalies(self, context: PacketContext) -> List[DetectionFinding]:
        if context.category not in {"HTTP", "HTTPS"} or not context.http_method:
            return []
        findings: List[DetectionFinding] = []
        user_agent = context.http_user_agent.lower()
        if any(marker in user_agent for marker in SUSPICIOUS_USER_AGENTS):
            findings.append(
                DetectionFinding(
                    title="Suspicious HTTP user-agent",
                    severity="MEDIUM",
                    classification="HTTP anomaly",
                    score_delta=4,
                    reasons=[
                        f"Observed user-agent: {context.http_user_agent or '(empty)'}",
                        "The user-agent matches common automation or offensive tooling.",
                    ],
                    action="Review the initiating process and verify whether scripted access is expected.",
                    mitre_technique="T1071",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"http-ua:{context.src_ip}:{context.http_user_agent}",
                )
            )
        body_preview = context.payload_preview.lower()
        if context.http_method == "POST" and context.http_body_size > 50_000:
            findings.append(
                DetectionFinding(
                    title="Large HTTP POST request",
                    severity="MEDIUM",
                    classification="HTTP anomaly",
                    score_delta=5,
                    reasons=[
                        f"POST body size reached {format_bytes(context.http_body_size)}.",
                        "Large uploads can indicate bulk transfer or staged exfiltration.",
                    ],
                    action="Check whether the destination and uploaded data are expected for this host.",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    dedupe_key=f"http-post-size:{context.src_ip}:{context.dst_ip}",
                )
            )
        if BASE64_BLOB_RE.search(context.payload_preview):
            findings.append(
                DetectionFinding(
                    title="Encoded blob in HTTP payload",
                    severity="HIGH",
                    classification="HTTP anomaly",
                    score_delta=6,
                    reasons=[
                        "A long base64-like blob was found in the HTTP request body or query.",
                    ],
                    action="Inspect the request body for encoded credentials, payloads, or exfiltrated data.",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    dedupe_key=f"http-base64:{context.src_ip}:{context.dst_ip}",
                )
            )
        url_blob = f"{context.http_url} {context.http_query_string}".lower()
        if any(pattern in url_blob for pattern in DIRECTORY_TRAVERSAL_PATTERNS):
            findings.append(
                DetectionFinding(
                    title="Directory traversal attempt",
                    severity="HIGH",
                    classification="Web exploitation",
                    score_delta=7,
                    reasons=[
                        f"Suspicious path traversal pattern detected in URL {context.http_url}.",
                    ],
                    action="Inspect the target application logs and block the source if unauthorized.",
                    mitre_technique="T1190",
                    mitre_tactic="Initial Access",
                    dedupe_key=f"http-traversal:{context.src_ip}:{context.dst_ip}",
                )
            )
        if any(pattern in url_blob or pattern in body_preview for pattern in SQLI_PATTERNS):
            findings.append(
                DetectionFinding(
                    title="Possible SQL injection pattern",
                    severity="HIGH",
                    classification="Web exploitation",
                    score_delta=7,
                    reasons=[
                        f"SQL injection indicators were observed in the URL or request body for {context.http_url}.",
                    ],
                    action="Inspect the web application, review WAF logs, and contain the source if malicious.",
                    mitre_technique="T1190",
                    mitre_tactic="Initial Access",
                    dedupe_key=f"http-sqli:{context.src_ip}:{context.dst_ip}",
                )
            )
        return findings

    def _detect_beaconing(self, context: PacketContext) -> List[DetectionFinding]:
        if context.direction != "outbound" or is_private_or_local(context.dst_ip):
            return []
        key = (context.src_ip, context.dst_ip, context.dst_port, context.transport)
        flow = self.flows[key]
        should_record = False
        if context.transport == "TCP":
            should_record = bool(context.tcp_flags & 0x02 and not context.tcp_flags & 0x10)
        elif context.transport == "UDP":
            should_record = context.timestamp - flow.last_seen >= 5
        flow.last_seen = context.timestamp
        if not should_record:
            return []
        flow.times.append(context.timestamp)
        if len(flow.times) < self.config.beacon_min_samples:
            return []
        intervals = [flow.times[index] - flow.times[index - 1] for index in range(1, len(flow.times))]
        mean = statistics.mean(intervals)
        stddev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        jitter = stddev / mean if mean else 1.0
        if mean < 10 or mean > 3600 or jitter > self.config.beacon_max_jitter:
            return []
        return [
            DetectionFinding(
                title="Regular beaconing pattern",
                severity="HIGH",
                classification="Command and control",
                score_delta=8,
                reasons=[
                    f"Observed {len(flow.times)} callbacks to {context.dst_ip}:{context.dst_port} with average interval {mean:.1f}s.",
                    f"Timing jitter remained low at {jitter:.2f}.",
                ],
                action="Investigate for scheduled C2 beacons, unauthorized agents, or malware implants.",
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                dedupe_key=f"beacon:{context.src_ip}:{context.dst_ip}:{context.dst_port}:{context.transport}",
                auto_block=True,
                cooldown=600,
            )
        ]

    def _detect_exfiltration(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if context.direction == "outbound" and not is_private_or_local(context.dst_ip):
            total_outbound = sum_bytes(state.outbound_bytes)
            destination_outbound = sum_bytes(state.outbound_dest_bytes[context.dst_ip])
            if destination_outbound >= self.config.exfil_bytes_high:
                findings.append(
                    DetectionFinding(
                        title="Large outbound transfer",
                        severity="CRITICAL",
                        classification="Data exfiltration",
                        score_delta=10,
                        reasons=[
                            f"{format_bytes(destination_outbound)} was sent to {context.dst_ip} inside {self.config.exfil_window} seconds.",
                            f"Aggregate outbound volume for the host is {format_bytes(total_outbound)}.",
                        ],
                        action="Isolate the host, inspect active sessions, and confirm whether the transfer is authorized.",
                        mitre_technique="T1048",
                        mitre_tactic="Exfiltration",
                        dedupe_key=f"exfil-high:{context.src_ip}:{context.dst_ip}",
                        auto_block=True,
                        cooldown=300,
                    )
                )
            elif destination_outbound >= self.config.exfil_bytes_medium and not context.trusted:
                findings.append(
                    DetectionFinding(
                        title="Elevated outbound transfer",
                        severity="HIGH",
                        classification="Data exfiltration",
                        score_delta=7,
                        reasons=[
                            f"{format_bytes(destination_outbound)} was transferred to {context.dst_ip} within {self.config.exfil_window} seconds.",
                        ],
                        action="Validate the destination and inspect whether the upload aligns with user activity.",
                        mitre_technique="T1048",
                        mitre_tactic="Exfiltration",
                        dedupe_key=f"exfil-medium:{context.src_ip}:{context.dst_ip}",
                        cooldown=240,
                    )
                )
        return findings

    def _detect_baseline_deviation(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        if not state.snapshot.baseline_ready:
            return []
        findings: List[DetectionFinding] = []
        destination_seen = state.baseline_destinations[context.hostname or context.dst_ip]
        port_seen = state.baseline_ports[context.dst_port]
        protocol_seen = state.baseline_protocols[context.category]
        if destination_seen <= 1 and context.direction == "outbound" and not context.trusted:
            findings.append(
                DetectionFinding(
                    title="New external destination outside baseline",
                    severity="LOW",
                    classification="Baseline deviation",
                    score_delta=2,
                    reasons=[
                        f"{context.hostname or context.dst_ip} has not been common for {context.src_ip}.",
                    ],
                    action="Confirm whether the destination is legitimate and expected for the host role.",
                    mitre_technique="T1071",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"baseline-dest:{context.src_ip}:{context.hostname or context.dst_ip}",
                    cooldown=600,
                )
            )
        if port_seen <= 1 and context.direction == "outbound":
            findings.append(
                DetectionFinding(
                    title="New service port outside baseline",
                    severity="LOW",
                    classification="Baseline deviation",
                    score_delta=2,
                    reasons=[
                        f"Port {context.dst_port} is not part of the host's usual communication pattern.",
                    ],
                    action="Review whether a new application or service was recently introduced on the host.",
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    dedupe_key=f"baseline-port:{context.src_ip}:{context.dst_port}",
                    cooldown=600,
                )
            )
        if protocol_seen <= 1 and context.category not in {"TCP", "UDP"}:
            findings.append(
                DetectionFinding(
                    title="Unusual protocol for host baseline",
                    severity="LOW",
                    classification="Baseline deviation",
                    score_delta=2,
                    reasons=[
                        f"{context.category} traffic has been rarely seen for {context.src_ip}.",
                    ],
                    action="Validate whether the observed protocol matches the device role.",
                    mitre_technique="T1046",
                    mitre_tactic="Discovery",
                    dedupe_key=f"baseline-protocol:{context.src_ip}:{context.category}",
                    cooldown=600,
                )
            )
        return findings

    def _detect_ml_anomaly(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        if IsolationForest is None or len(self.ml_features) < 200:
            return []
        if self.ml_model is None or len(self.ml_features) - self.ml_last_train_count >= 100:
            self.ml_model = IsolationForest(contamination=0.02, random_state=42)
            self.ml_model.fit(list(self.ml_features))
            self.ml_last_train_count = len(self.ml_features)
        sample = list(state.feature_samples)[-1] if state.feature_samples else None
        if sample is None:
            return []
        prediction = int(self.ml_model.predict([sample])[0])
        if prediction != -1:
            return []
        return [
            DetectionFinding(
                title="ML traffic outlier",
                severity="MEDIUM",
                classification="Machine learning anomaly",
                score_delta=4,
                reasons=[
                    "Isolation Forest marked the latest packet feature vector as an outlier against learned traffic patterns.",
                    f"Features: size={context.packet_len}, port={context.dst_port}, ttl={context.ttl}.",
                ],
                action="Use supporting detections and baseline context to determine whether the outlier is benign or malicious.",
                mitre_technique="T1001",
                mitre_tactic="Defense Evasion",
                dedupe_key=f"ml-outlier:{context.src_ip}:{context.dst_ip}:{context.dst_port}",
                cooldown=300,
            )
        ]

    def _detect_protocol_activity(self, context: PacketContext) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        if context.category == "SMB" and "NTLMSSP" in context.payload_preview.upper():
            findings.append(
                DetectionFinding(
                    title="SMB authentication exchange observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=["NTLMSSP markers were present in SMB traffic, indicating an authentication workflow."],
                    action="Use this as investigative context if the session becomes suspicious.",
                    mitre_technique="T1110",
                    mitre_tactic="Credential Access",
                    dedupe_key=f"smb-auth:{context.session_id}",
                    cooldown=1200,
                )
            )
        if context.category == "RDP" and "COOKIE: MSTSHASH" in context.payload_preview.upper():
            findings.append(
                DetectionFinding(
                    title="RDP client negotiation observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=["RDP negotiation markers were observed in the payload preview."],
                    action="Review if remote desktop usage aligns with the host role and change window.",
                    mitre_technique="T1021",
                    mitre_tactic="Lateral Movement",
                    dedupe_key=f"rdp-negotiation:{context.session_id}",
                    cooldown=1200,
                )
            )
        if context.category == "KERBEROS":
            findings.append(
                DetectionFinding(
                    title="Kerberos service observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=["Kerberos traffic was observed, which can be useful context during identity investigations."],
                    action="Correlate with authentication telemetry if the host later triggers credential-focused alerts.",
                    mitre_technique="T1558",
                    mitre_tactic="Credential Access",
                    dedupe_key=f"kerberos:{context.session_id}",
                    cooldown=1800,
                )
            )
        return findings

    def _apply_findings(self, state: HostState, context: PacketContext, findings: List[DetectionFinding]) -> None:
        for finding in findings:
            state.snapshot.score = min(100, state.snapshot.score + finding.score_delta)
            state.snapshot.severity = self._severity_from_score(state.snapshot.score, preferred=finding.severity)
            state.snapshot.last_finding = finding.title
            state.recent_findings.appendleft(finding.title)

            if not self.router.should_emit(
                AlertRecord(
                    timestamp=context.timestamp,
                    host=context.src_ip,
                    destination=self._destination_label(context),
                    severity=finding.severity,
                    title=finding.title,
                    classification=finding.classification,
                    score=state.snapshot.score,
                    reasons=finding.reasons,
                    action=finding.action,
                    mitre_technique=finding.mitre_technique,
                    mitre_tactic=finding.mitre_tactic,
                    geo=context.geo,
                    iocs=finding.iocs,
                    dedupe_key=finding.dedupe_key,
                    session_id=context.session_id,
                ),
                finding.cooldown,
            ):
                continue

            occurrences = self.router.get_occurrences(finding.dedupe_key)
            alert = AlertRecord(
                timestamp=context.timestamp,
                host=context.src_ip,
                destination=self._destination_label(context),
                severity=self._severity_from_score(state.snapshot.score, preferred=finding.severity),
                title=finding.title if not finding.aggregate_value else f"{finding.title}: {finding.aggregate_value}",
                classification=finding.classification,
                score=state.snapshot.score,
                reasons=finding.reasons,
                action=finding.action,
                mitre_technique=finding.mitre_technique,
                mitre_tactic=finding.mitre_tactic,
                geo=context.geo,
                iocs=finding.iocs,
                dedupe_key=finding.dedupe_key,
                occurrences=occurrences,
                recommended_block=self._block_rule(context) if finding.auto_block else "",
                session_id=context.session_id,
            )
            self.alert_count += 1
            self.store.insert_alert(alert)
            self.router.emit(alert)

    def _persist_baseline_if_needed(self, state: HostState, timestamp: float) -> None:
        if state.snapshot.packet_count % 25 != 0:
            return
        payload = {
            "destinations": state.baseline_destinations.most_common(20),
            "ports": state.baseline_ports.most_common(20),
            "protocols": state.baseline_protocols.most_common(20),
            "score": state.snapshot.score,
            "reputation_score": state.snapshot.reputation_score,
        }
        self.store.upsert_baseline(state.snapshot.ip, timestamp, payload)

    def _destination_label(self, context: PacketContext) -> str:
        host_label = context.hostname if context.hostname and context.hostname != context.dst_ip else ""
        if host_label:
            return f"{context.dst_ip}:{context.dst_port} ({host_label})"
        return f"{context.dst_ip}:{context.dst_port}"

    def _block_rule(self, context: PacketContext) -> str:
        block_target = context.dst_ip if context.direction == "outbound" else context.src_ip
        return f"iptables -A INPUT -s {block_target} -j DROP"

    def _severity_from_score(self, score: int, preferred: str = "LOW") -> str:
        derived = "LOW"
        if score >= 35:
            derived = "CRITICAL"
        elif score >= 20:
            derived = "HIGH"
        elif score >= 10:
            derived = "MEDIUM"
        if SEVERITY_ORDER.get(preferred, 0) > SEVERITY_ORDER.get(derived, 0):
            return preferred
        return derived
