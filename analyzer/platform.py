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
import traceback
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from .config import PlatformConfig
from .intel import ThreatIntelManager, normalize_domain
from .models import AlertRecord, DetectionFinding, HostSnapshot, PacketContext, SessionRecord
from .output import AlertRouter
from .reporting import ReportGenerator
from .storage import create_store

try:
    from geoip2.database import Reader as GeoIPReader
except Exception:
    GeoIPReader = None

try:
    from scapy.all import DNS, Ether, IP, IPv6, PcapReader, Raw, TCP, UDP, get_if_list, sniff
    SCAPY_IMPORT_ERROR = None
except Exception as exc:
    DNS = None
    Ether = None
    IP = None
    IPv6 = None
    PcapReader = None
    Raw = None
    TCP = None
    UDP = None
    get_if_list = None
    sniff = None
    SCAPY_IMPORT_ERROR = exc

try:
    import dpkt
    DPKT_IMPORT_ERROR = None
except Exception as exc:
    dpkt = None
    DPKT_IMPORT_ERROR = exc

try:
    import pyshark
    PYSHARK_IMPORT_ERROR = None
except Exception as exc:
    pyshark = None
    PYSHARK_IMPORT_ERROR = exc

try:
    from cryptography import x509
except Exception:
    x509 = None

try:
    from sklearn.ensemble import IsolationForest
except Exception:
    IsolationForest = None

try:
    import numpy as np
    from tensorflow.keras.layers import Dense, LSTM
    from tensorflow.keras.models import Sequential
except Exception as exc:
    np = None
    Dense = None
    LSTM = None
    Sequential = None
    TENSORFLOW_IMPORT_ERROR = exc
else:
    TENSORFLOW_IMPORT_ERROR = None


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
FTP_PORTS = {20, 21}
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
DOWNLOAD_CONTENT_TYPES = (
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
    "application/pdf",
    "application/msword",
    "application/vnd",
    "image/",
    "audio/",
    "video/",
)
SMB2_COMMANDS = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0003: "TREE_CONNECT",
    0x0005: "CREATE",
    0x0008: "READ",
    0x0009: "WRITE",
    0x000B: "IOCTL",
    0x000D: "ECHO",
}
LDAP_OPERATION_TAGS = {
    0x60: "bindRequest",
    0x61: "bindResponse",
    0x63: "searchRequest",
    0x64: "searchResultEntry",
    0x65: "searchResultDone",
    0x66: "modifyRequest",
    0x68: "addRequest",
}
KERBEROS_MESSAGE_TYPES = {
    0x6A: "AS-REQ",
    0x6B: "AS-REP",
    0x6C: "TGS-REQ",
    0x6D: "TGS-REP",
    0x6E: "AP-REQ",
    0x6F: "AP-REP",
}
SERVICE_PORT_LABELS = {
    20: "ftp-data",
    21: "ftp-control",
    53: "dns",
    80: "http",
    88: "kerberos",
    123: "ntp",
    139: "netbios",
    389: "ldap",
    443: "https",
    445: "smb",
    636: "ldaps",
    3389: "rdp",
    5222: "xmpp",
    5223: "xmpps",
    5228: "push",
    6667: "irc",
    6881: "bittorrent",
    8080: "web-alt",
    8443: "https-alt",
    51413: "bittorrent",
}
FTP_TRANSFER_TIMEOUT = 900
KNOWN_SERVICE_PORTS = HTTP_PORTS | HTTPS_PORTS | DNS_PORTS | IRC_PORTS | P2P_PORTS | SMB_PORTS | RDP_PORTS | LDAP_PORTS | KERBEROS_PORTS | FTP_PORTS


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
    transition_counts: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    transition_totals: Counter = field(default_factory=Counter)
    sequence_tokens: Deque[str] = field(default_factory=lambda: deque(maxlen=512))
    last_sequence_token: str = ""
    last_packet_time: float = 0.0
    last_seen: float = field(default_factory=time.time)


@dataclass
class FlowState:
    times: Deque[float] = field(default_factory=lambda: deque(maxlen=16))
    last_seen: float = 0.0
    last_sni: str = ""
    server_names: List[str] = field(default_factory=list)


@dataclass
class ReassemblyBuffer:
    next_seq: Optional[int] = None
    fragments: Dict[int, bytes] = field(default_factory=dict)
    overlaps: int = 0
    out_of_order: int = 0
    contiguous_bytes: int = 0


class LSTMSequenceModel:
    def __init__(self):
        self.model = None
        self.token_to_id: Dict[str, int] = {}
        self.last_train_count = 0
        self.error = ""

    @property
    def available(self) -> bool:
        return np is not None and Sequential is not None and LSTM is not None and Dense is not None

    def _encode_token(self, token: str) -> int:
        if token not in self.token_to_id:
            self.token_to_id[token] = len(self.token_to_id)
        return self.token_to_id[token]

    def train(self, tokens: List[str], sequence_length: int, epochs: int = 2) -> None:
        if not self.available:
            self.error = f"TensorFlow/Keras unavailable: {TENSORFLOW_IMPORT_ERROR}"
            return
        encoded = [self._encode_token(token) for token in tokens if token]
        vocab_size = max(2, len(self.token_to_id))
        if len(encoded) <= sequence_length or vocab_size <= 1:
            return
        x_rows = []
        y_rows = []
        for index in range(sequence_length, len(encoded)):
            x_rows.append(encoded[index - sequence_length:index])
            y_rows.append(encoded[index])
        x_train = np.array(x_rows, dtype="float32").reshape((len(x_rows), sequence_length, 1))
        x_train = x_train / float(max(1, vocab_size - 1))
        y_train = np.array(y_rows, dtype="int32")
        model = Sequential()
        model.add(LSTM(32, input_shape=(sequence_length, 1)))
        model.add(Dense(vocab_size, activation="softmax"))
        model.compile(optimizer="adam", loss="sparse_categorical_crossentropy")
        model.fit(x_train, y_train, epochs=epochs, verbose=0)
        self.model = model
        self.last_train_count = len(encoded)
        self.error = ""

    def probability(self, previous_tokens: List[str], current_token: str, sequence_length: int) -> Optional[float]:
        if not self.available or self.model is None or current_token not in self.token_to_id:
            return None
        if len(previous_tokens) < sequence_length:
            return None
        encoded = [self.token_to_id.get(token, 0) for token in previous_tokens[-sequence_length:]]
        vocab_size = max(2, len(self.token_to_id))
        x_value = np.array([encoded], dtype="float32").reshape((1, sequence_length, 1))
        x_value = x_value / float(max(1, vocab_size - 1))
        prediction = self.model.predict(x_value, verbose=0)[0]
        token_id = self.token_to_id[current_token]
        if token_id >= len(prediction):
            return None
        return float(prediction[token_id])


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
    mapping = {
        "TCP": 1,
        "UDP": 2,
        "DNS": 3,
        "HTTP": 4,
        "HTTPS": 5,
        "TLS": 6,
        "FTP": 7,
        "SMB": 8,
        "RDP": 9,
        "LDAP": 10,
        "KERBEROS": 11,
        "IRC": 12,
        "P2P": 13,
        "MDNS": 14,
        "mDNS": 14,
    }
    return mapping.get(transport, 0)


def direction_code(direction: str) -> int:
    mapping = {"outbound": 1, "inbound": 2, "internal": 3, "external": 4}
    return mapping.get(direction, 0)


def normalize_session_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, transport: str) -> str:
    endpoints = [(src_ip, src_port), (dst_ip, dst_port)]
    left, right = sorted(endpoints)
    return f"{left[0]}:{left[1]}-{right[0]}:{right[1]}-{transport}"


def safe_path_fragment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def redact_connection_target(value: str) -> str:
    if "://" in value and "@" in value:
        prefix, tail = value.split("://", 1)
        if "@" in tail:
            _, host = tail.rsplit("@", 1)
            return f"{prefix}://***@{host}"
    return value


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
            "content_type": headers.get("content-type", ""),
            "content_disposition": headers.get("content-disposition", ""),
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


def parse_ftp_payload(payload: bytes) -> Dict[str, object]:
    if not payload:
        return {}
    text = payload[:4096].decode("utf-8", errors="ignore").strip()
    if not text:
        return {}
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return {}
    first_line = lines[0]
    details: Dict[str, object] = {"preview": first_line[:220]}
    if len(first_line) >= 3 and first_line[:3].isdigit():
        details["is_response"] = True
        details["status_code"] = first_line[:3]
        details["message"] = first_line[4:220] if len(first_line) > 4 else ""
        return details
    command, _, argument = first_line.partition(" ")
    command = command.upper()
    if command not in {
        "USER", "PASS", "CWD", "PWD", "LIST", "NLST", "RETR", "STOR", "DELE", "RNFR", "RNTO",
        "PASV", "PORT", "EPSV", "TYPE", "SIZE", "SYST", "MKD", "RMD",
    }:
        return {}
    details["is_response"] = False
    details["command"] = command
    details["argument"] = argument[:220]
    if command in {"RETR", "STOR", "RNFR", "RNTO", "DELE"} and argument:
        details["file_name"] = safe_path_fragment(Path(argument).name or argument)
    if command == "USER" and argument:
        details["username"] = argument[:120]
    return details


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


def extract_printable_strings(payload: bytes, minimum: int = 5) -> List[str]:
    text = safe_decode(payload)
    return re.findall(rf"[A-Za-z0-9_./:\\\\@-]{{{minimum},}}", text)


def parse_smb_payload(payload: bytes) -> Dict[str, object]:
    details: Dict[str, object] = {}
    if len(payload) >= 4 and payload[:4] == b"\xfeSMB":
        details["dialect"] = "SMB2+"
        if len(payload) >= 14:
            command = int.from_bytes(payload[12:14], "little")
            details["command"] = SMB2_COMMANDS.get(command, f"0x{command:04x}")
    elif len(payload) >= 4 and payload[:4] == b"\xffSMB":
        details["dialect"] = "SMB1"
        if len(payload) >= 5:
            details["command"] = f"0x{payload[4]:02x}"
    elif b"NTLMSSP" not in payload.upper():
        return {}

    upper = payload.upper()
    if b"NTLMSSP" in upper:
        details["auth"] = "NTLMSSP"
    share_paths = []
    for token in extract_printable_strings(payload, minimum=6):
        if token.startswith("\\\\") and token.count("\\") >= 2:
            share_paths.append(token)
    if share_paths:
        details["shares"] = share_paths[:5]
    return details


def parse_rdp_payload(payload: bytes) -> Dict[str, object]:
    details: Dict[str, object] = {}
    preview = safe_decode(payload[:512])
    upper = preview.upper()
    if payload[:1] == b"\x03":
        details["transport"] = "TPKT"
    if "COOKIE: MSTSHASH=" in upper:
        details["stage"] = "client-negotiation"
        match = re.search(r"cookie:\s*mstshash=([^\r\n;]+)", preview, re.IGNORECASE)
        if match:
            details["client_name"] = match.group(1)
    channels = []
    if "RDPDR" in upper:
        channels.append("rdpdr")
    if "CLIPRDR" in upper:
        channels.append("cliprdr")
    if channels:
        details["virtual_channels"] = channels
    return details


def parse_ldap_payload(payload: bytes) -> Dict[str, object]:
    if not payload or payload[0] != 0x30:
        return {}
    details: Dict[str, object] = {}
    for byte, label in LDAP_OPERATION_TAGS.items():
        if bytes([byte]) in payload[:48]:
            details["operation"] = label
            break
    preview = safe_decode(payload[:1024])
    distinguished_names = re.findall(
        r"(?:CN|OU|DC)=[^,\r\n]+(?:,(?:CN|OU|DC)=[^,\r\n]+)+",
        preview,
        re.IGNORECASE,
    )
    if distinguished_names:
        details["distinguished_names"] = distinguished_names[:4]
    if b"\x80" in payload[:80]:
        details["simple_bind"] = True
    return details


def parse_kerberos_payload(payload: bytes) -> Dict[str, object]:
    if not payload:
        return {}
    details: Dict[str, object] = {}
    if payload[0] in KERBEROS_MESSAGE_TYPES:
        details["message_type"] = KERBEROS_MESSAGE_TYPES[payload[0]]
    principals = []
    for token in extract_printable_strings(payload[:1024], minimum=5):
        lowered = token.lower()
        if "/" in token and any(lowered.startswith(prefix) for prefix in ("cifs/", "host/", "ldap/", "http/", "termsrv/")):
            principals.append(token)
        elif "krbtgt" in lowered:
            principals.append(token)
    if principals:
        details["service_principals"] = principals[:6]
    return details


class GeoIPResolver:
    def __init__(self, database_path: str):
        self.reader = None
        self.cache: Dict[str, str] = {}
        self.detail_cache: Dict[str, Dict[str, object]] = {}
        self.status = "GeoIP disabled"
        self.database_path = ""
        self.reload(database_path)

    def _resolve_database_path(self, database_path: str) -> str:
        raw = (database_path or os.getenv("GEOIP_DB", "")).strip().strip('"')
        if not raw:
            return ""
        expanded = Path(raw).expanduser()
        candidates: List[Path] = []
        if expanded.is_dir():
            candidates.extend(sorted(expanded.glob("GeoLite2-*.mmdb")))
            candidates.extend(sorted(expanded.glob("*.mmdb")))
        else:
            candidates.append(expanded)
            if expanded.suffix.lower() != ".mmdb":
                candidates.append(expanded.with_suffix(".mmdb"))
                candidates.append(expanded.parent / f"{expanded.name}.mmdb")
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file():
                    return str(candidate.resolve())
            except OSError:
                continue
        return str(expanded)

    def reload(self, database_path: str) -> None:
        requested_path = database_path or os.getenv("GEOIP_DB", "")
        self.database_path = self._resolve_database_path(requested_path)
        self.cache = {}
        self.detail_cache = {}
        if self.reader is not None:
            try:
                self.reader.close()
            except Exception:
                pass
        self.reader = None
        self.status = "GeoIP disabled"
        if not self.database_path:
            self.status = "GeoIP disabled (no database configured)"
            return
        if GeoIPReader is None:
            self.status = "GeoIP disabled (geoip2 not installed)"
            return
        if not Path(self.database_path).exists():
            self.status = f"GeoIP disabled (database not found: {self.database_path})"
            return
        try:
            self.reader = GeoIPReader(self.database_path)
            self.status = f"GeoIP enabled using {self.database_path}"
        except Exception as exc:
            self.status = f"GeoIP disabled ({exc})"

    def lookup_detail(self, ip_value: str) -> Dict[str, object]:
        if ip_value in self.detail_cache:
            return self.detail_cache[ip_value]
        if is_private_or_local(ip_value):
            detail = {"geo": "Private/Local", "country": "Private/Local", "city": "", "latitude": None, "longitude": None}
            self.detail_cache[ip_value] = detail
            self.cache[ip_value] = "Private/Local"
            return detail
        if self.reader is None:
            detail = {"geo": "GeoIP unavailable", "country": "", "city": "", "latitude": None, "longitude": None}
            self.detail_cache[ip_value] = detail
            self.cache[ip_value] = "GeoIP unavailable"
            return detail
        try:
            record = self.reader.city(ip_value)
            country = record.country.iso_code or record.country.name or "Unknown"
            city = record.city.name or ""
            value = country if not city else f"{country} / {city}"
            detail = {
                "geo": value,
                "country": country,
                "city": city,
                "latitude": record.location.latitude,
                "longitude": record.location.longitude,
            }
        except Exception:
            detail = {"geo": "Unknown", "country": "Unknown", "city": "", "latitude": None, "longitude": None}
        self.detail_cache[ip_value] = detail
        self.cache[ip_value] = str(detail["geo"])
        return detail

    def lookup(self, ip_value: str) -> str:
        if ip_value in self.cache:
            return self.cache[ip_value]
        return str(self.lookup_detail(ip_value).get("geo") or "Unknown")


class ThreatPlatform:
    def __init__(self, config: PlatformConfig):
        self.config = config
        self.config.ensure_directories()
        self.store = create_store(config.database_path, config.storage_backend)
        self.router = AlertRouter(config)
        self.intel = ThreatIntelManager(config.ioc_sources)
        self.intel.load_all()
        self.geoip = GeoIPResolver(config.geoip_db)
        self.hosts: Dict[str, HostState] = {}
        self.flows: Dict[Tuple[str, str, int, str], FlowState] = defaultdict(FlowState)
        self.sessions: Dict[str, SessionRecord] = {}
        self.tls_client_hello: Dict[str, Dict[str, object]] = {}
        self.reassembly_buffers: Dict[Tuple[str, str], ReassemblyBuffer] = defaultdict(ReassemblyBuffer)
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
        self.last_capture_error = ""
        self.hostname_cache: Dict[str, str] = {}
        self.pending_artifacts: Dict[str, Dict[str, object]] = {}
        self.pending_ftp_transfers: Dict[Tuple[str, str], Dict[str, object]] = {}
        self.alert_count = 0
        self.packet_count = 0
        self.generated_report_count = 0
        self.ml_model = None
        self.ml_features: Deque[List[float]] = deque(maxlen=2048)
        self.ml_last_train_count = 0
        self.sequence_tokens_global: Deque[str] = deque(maxlen=4096)
        self.lstm_model = LSTMSequenceModel()
        self.closed = False

    def start_workers(self) -> None:
        self.worker_threads = [thread for thread in self.worker_threads if thread.is_alive()]
        if not self.capture_threads:
            self.last_capture_error = ""
        missing = max(1, self.config.worker_count) - len(self.worker_threads)
        for index in range(max(0, missing)):
            thread = threading.Thread(target=self._worker_loop, name=f"worker-{index}", daemon=True)
            thread.start()
            self.worker_threads.append(thread)

    def _discard_pending_packets(self) -> int:
        dropped = 0
        while True:
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break
            self.packet_queue.task_done()
            dropped += 1
        return dropped

    def stop_capture(self, drain_timeout: float = 3.0, discard_pending: bool = True) -> None:
        self.stop_event.set()
        if discard_pending:
            self._discard_pending_packets()
        deadline = time.time() + max(0.5, drain_timeout)
        for thread in self.capture_threads:
            remaining = max(0.0, deadline - time.time())
            if remaining <= 0:
                break
            thread.join(timeout=min(1.25, remaining))
        while not discard_pending and time.time() < deadline:
            if self.packet_queue.unfinished_tasks == 0:
                break
            time.sleep(0.05)
        for thread in self.worker_threads:
            remaining = max(0.0, deadline - time.time())
            if remaining <= 0:
                break
            thread.join(timeout=min(1.0, remaining))
        self.capture_threads = [thread for thread in self.capture_threads if thread.is_alive()]
        self.worker_threads = [thread for thread in self.worker_threads if thread.is_alive()]
        if not self.capture_threads and not self.worker_threads:
            self.stop_event.clear()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.geoip.reader is not None:
            try:
                self.geoip.reader.close()
            except Exception:
                pass
        self.store.close()

    def stop(self) -> None:
        self.stop_capture()
        if self.config.save_reports_on_exit:
            self.generate_reports()
        self.close()

    def snapshot_hosts(self) -> List[HostSnapshot]:
        with self.lock:
            rows = [state.snapshot for state in self.hosts.values()]
        return sorted(rows, key=lambda row: (-row.score, -row.packet_count, row.ip))

    def summary(self) -> Dict[str, object]:
        model = self.model_status()
        return {
            "packets_processed": self.packet_count,
            "alerts_generated": self.alert_count,
            "geoip_status": self.geoip.status,
            "tracked_hosts": len(self.hosts),
            "tracked_sessions": len(self.sessions),
            "ioc_count": len(self.intel.ip_feeds) + len(self.intel.domain_feeds),
            "database_backend": getattr(self.store, "backend", "sqlite"),
            "database_driver": getattr(self.store, "driver", "sqlite3"),
            "database_target": redact_connection_target(self.config.database_path),
            "packet_parser": self.config.packet_parser,
            "ml_status": model["isolation_forest"],
            "sequence_model_status": model["sequence_model"],
            "lstm_model_status": model["lstm_sequence_model"],
        }

    def dashboard_snapshot(self) -> Dict[str, object]:
        hosts = [row.to_dict() for row in self.snapshot_hosts()[:20]]
        sessions = self.store.fetch_sessions(limit=20)
        edges: List[Dict[str, object]] = []
        for session in sessions[:12]:
            edges.append(
                {
                    "source": session["src_ip"],
                    "target": session["dst_ip"],
                    "label": f"{session['transport']}:{session['dst_port']}",
                    "bytes": session["total_bytes"],
                }
            )
        return {
            "summary": self.summary(),
            "severity_counts": self.store.fetch_alert_counts(),
            "protocol_distribution": self.store.fetch_protocol_distribution(),
            "top_talkers": self.store.fetch_top_talkers(),
            "geo_summary": self.store.fetch_geo_summary(),
            "top_risky": self.store.fetch_top_riskiest(),
            "mitre_heatmap": self.store.fetch_mitre_heatmap(),
            "hosts": hosts,
            "alerts": self.store.fetch_alerts(limit=30),
            "timeline": self.store.fetch_alert_timeline(limit=40),
            "sessions": sessions,
            "topology": edges,
            "traffic_series": self.store.fetch_time_series("events", hours=self.config.hunt_default_hours, bucket_minutes=15),
            "alert_series": self.store.fetch_time_series("alerts", hours=self.config.hunt_default_hours, bucket_minutes=15),
            "artifacts": self.store.fetch_artifacts(limit=30),
            "hunt_summary": self.store.fetch_hunt_summary(self.config.hunt_default_hours),
            "asset_inventory": self.store.fetch_asset_inventory(limit=self.config.asset_inventory_limit),
            "baseline_profiles": self.store.fetch_baseline_profiles(limit=self.config.baseline_profile_limit),
            "saved_hunts": self.store.fetch_saved_hunts(limit=self.config.max_saved_hunts),
            "long_term_trends": self.store.fetch_long_term_trends(days=self.config.long_term_trend_days),
            "live_capture_active": any(thread.is_alive() for thread in self.capture_threads),
            "capture_error": self.last_capture_error,
            "dashboard_refresh_seconds": self.config.dashboard_refresh_seconds,
            "feed_status": self.feed_status(),
            "model_status": self.model_status(),
        }

    def capture_active(self) -> bool:
        return any(thread.is_alive() for thread in self.capture_threads)

    def available_interfaces(self) -> List[str]:
        if get_if_list is None:
            return []
        try:
            return [str(item) for item in get_if_list()]
        except Exception:
            return []

    def launcher_settings(self) -> Dict[str, object]:
        return {
            "interfaces": self.config.interfaces,
            "available_interfaces": self.available_interfaces(),
            "bpf_filter": self.config.bpf_filter,
            "quick_filter": self.config.quick_filter,
            "geoip_db": self.config.geoip_db,
            "dashboard_refresh_seconds": self.config.dashboard_refresh_seconds,
            "worker_count": self.config.worker_count,
            "ioc_sources": self.config.ioc_sources,
            "database_path": redact_connection_target(self.config.database_path),
            "storage_backend": self.config.storage_backend,
            "packet_parser": self.config.packet_parser,
            "report_dir": self.config.report_dir,
            "ml_enabled": self.config.ml_enabled,
            "sequence_model_enabled": self.config.sequence_model_enabled,
            "lstm_enabled": self.config.lstm_enabled,
        }

    def feed_status(self) -> List[Dict[str, object]]:
        return list(self.intel.feed_status)

    def apply_profile(self, profile_name: str) -> Dict[str, object]:
        profile = PlatformConfig.from_profile(profile_name)
        profile_updates = {
            "quick_filter": profile.quick_filter,
            "high_risk_countries": profile.high_risk_countries,
            "worker_count": profile.worker_count,
            "dns_tunnel_query_threshold": profile.dns_tunnel_query_threshold,
            "horizontal_port_threshold": profile.horizontal_port_threshold,
            "vertical_host_threshold": profile.vertical_host_threshold,
            "syn_scan_threshold": profile.syn_scan_threshold,
            "exfil_bytes_medium": profile.exfil_bytes_medium,
            "exfil_bytes_high": profile.exfil_bytes_high,
            "ioc_sources": profile.ioc_sources,
        }
        self.config = self.config.merge(profile_updates)
        self.intel = ThreatIntelManager(self.config.ioc_sources)
        self.intel.load_all()
        self.config.save_user_settings()
        return {
            "status": "applied",
            "profile": profile_name,
            "settings": self.launcher_settings(),
            "feed_status": self.feed_status(),
        }

    def model_status(self) -> Dict[str, object]:
        ready_hosts = sum(
            1
            for state in self.hosts.values()
            if state.snapshot.baseline_ready and len(state.feature_samples) >= self.config.ml_min_host_samples
        )
        sequence_ready_hosts = sum(
            1
            for state in self.hosts.values()
            if sum(state.transition_totals.values()) >= self.config.sequence_min_transitions
        )

        if not self.config.ml_enabled:
            isolation_state = "Disabled by operator"
        elif IsolationForest is None:
            isolation_state = "Unavailable (scikit-learn not installed)"
        elif len(self.ml_features) < self.config.ml_min_global_samples:
            isolation_state = f"Learning ({len(self.ml_features)}/{self.config.ml_min_global_samples} samples)"
        elif self.ml_model is None:
            isolation_state = "Ready to train"
        else:
            isolation_state = f"Ready ({self.ml_last_train_count} learned samples)"

        if not self.config.sequence_model_enabled:
            sequence_state = "Disabled by operator"
        elif sequence_ready_hosts <= 0:
            sequence_state = f"Learning ({self.config.sequence_min_transitions} transitions required)"
        else:
            sequence_state = f"Ready ({sequence_ready_hosts} hosts profiled)"

        if not self.config.lstm_enabled:
            lstm_state = "Disabled by operator"
        elif not self.lstm_model.available:
            lstm_state = f"Unavailable (tensorflow/keras not installed: {TENSORFLOW_IMPORT_ERROR})"
        elif len(self.sequence_tokens_global) < self.config.lstm_min_samples:
            lstm_state = f"Learning ({len(self.sequence_tokens_global)}/{self.config.lstm_min_samples} sequence tokens)"
        elif self.lstm_model.model is None:
            lstm_state = "Ready to train"
        else:
            lstm_state = f"Ready ({self.lstm_model.last_train_count} sequence tokens)"

        return {
            "ml_enabled": self.config.ml_enabled,
            "sequence_model_enabled": self.config.sequence_model_enabled,
            "isolation_forest": isolation_state,
            "sequence_model": sequence_state,
            "lstm_sequence_model": lstm_state,
            "global_samples": len(self.ml_features),
            "trained_samples": self.ml_last_train_count,
            "feature_dimensions": len(self.ml_features[-1]) if self.ml_features else 0,
            "baseline_ready_hosts": ready_hosts,
            "sequence_ready_hosts": sequence_ready_hosts,
            "lstm_tokens": len(self.sequence_tokens_global),
            "lstm_vocabulary": len(self.lstm_model.token_to_id),
        }

    def update_settings(self, updates: Dict[str, object]) -> Dict[str, object]:
        restart_required = False
        normalized: Dict[str, object] = {}
        if "interfaces" in updates:
            interfaces = updates.get("interfaces") or []
            if isinstance(interfaces, str):
                interfaces = [item.strip() for item in interfaces.split(",") if item.strip()]
            normalized["interfaces"] = list(interfaces)
            if normalized["interfaces"] != self.config.interfaces:
                restart_required = restart_required or self.capture_active()
        if "bpf_filter" in updates:
            normalized["bpf_filter"] = str(updates.get("bpf_filter") or "").strip()
            if normalized["bpf_filter"] != self.config.bpf_filter:
                restart_required = restart_required or self.capture_active()
        if "quick_filter" in updates:
            normalized["quick_filter"] = str(updates.get("quick_filter") or "all").strip() or "all"
        if "packet_parser" in updates:
            normalized["packet_parser"] = str(updates.get("packet_parser") or "scapy").strip().lower() or "scapy"
        if "dashboard_refresh_seconds" in updates:
            try:
                normalized["dashboard_refresh_seconds"] = max(2, min(60, int(updates.get("dashboard_refresh_seconds") or 5)))
            except (TypeError, ValueError):
                normalized["dashboard_refresh_seconds"] = self.config.dashboard_refresh_seconds
        if "worker_count" in updates:
            try:
                normalized["worker_count"] = max(1, min(8, int(updates.get("worker_count") or self.config.worker_count)))
            except (TypeError, ValueError):
                normalized["worker_count"] = self.config.worker_count
        if "ml_enabled" in updates:
            normalized["ml_enabled"] = as_bool(updates.get("ml_enabled"))
        if "sequence_model_enabled" in updates:
            normalized["sequence_model_enabled"] = as_bool(updates.get("sequence_model_enabled"))
        if "lstm_enabled" in updates:
            normalized["lstm_enabled"] = as_bool(updates.get("lstm_enabled"))
        if "geoip_db" in updates:
            normalized["geoip_db"] = str(updates.get("geoip_db") or "").strip()
        if "ioc_sources" in updates:
            sources = updates.get("ioc_sources") or []
            if isinstance(sources, str):
                sources = [item.strip() for item in sources.splitlines() if item.strip()]
            normalized["ioc_sources"] = list(sources)

        merged = self.config.merge(normalized)
        self.config = merged
        geoip_reenriched_events = 0
        if "geoip_db" in normalized:
            self.geoip.reload(self.config.geoip_db)
            if self.geoip.reader is not None:
                geoip_reenriched_events = self.store.rebuild_geoip(self.geoip.lookup, limit=5000)
                self.config.geoip_db = self.geoip.database_path
        if "ioc_sources" in normalized:
            self.intel = ThreatIntelManager(self.config.ioc_sources)
            self.intel.load_all()
        self.config.save_user_settings()
        return {
            "status": "saved",
            "restart_required": restart_required,
            "geoip_status": self.geoip.status,
            "geoip_reenriched_events": geoip_reenriched_events,
            "settings": self.launcher_settings(),
            "model_status": self.model_status(),
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
        self.generated_report_count += 1
        return generator.generate(self.summary(), self.snapshot_hosts())

    def benchmark_ingest(self, sample_count: Optional[int] = None) -> Dict[str, object]:
        total = max(100, int(sample_count or self.config.benchmark_default_packets))
        start = time.perf_counter()
        allowed = 0
        for index in range(total):
            payload = {
                "timestamp": time.time(),
                "src_ip": f"10.10.{index % 250}.{(index % 200) + 1}",
                "dst_ip": f"198.51.100.{(index % 200) + 1}",
                "src_port": 40000 + (index % 20000),
                "dst_port": [53, 80, 443, 445, 3389][index % 5],
                "transport": "UDP" if index % 5 == 0 else "TCP",
                "category": ["DNS", "HTTP", "TLS", "SMB", "RDP"][index % 5],
                "packet_len": 96 + (index % 1400),
                "detail": "benchmark synthetic context",
                "ttl": 64,
            }
            context = self.build_context_from_payload(payload)
            if self._allow_context(context):
                allowed += 1
                self._sequence_token(context)
        elapsed = max(time.perf_counter() - start, 0.000001)
        return {
            "mode": "dry-run",
            "packets": total,
            "allowed": allowed,
            "elapsed_seconds": round(elapsed, 4),
            "packets_per_second": int(total / elapsed),
            "note": "Measures normalization, IOC lookup, GeoIP lookup cache, quick-filter checks, and sequence tokenization without writing events.",
        }

    def replay_pcap(self, pcap_path: str, playback_speed: Optional[float] = None) -> None:
        parser = (self.config.packet_parser or "scapy").lower()
        if parser == "dpkt":
            self.replay_pcap_dpkt(pcap_path, playback_speed)
            return
        if parser == "pyshark":
            self.replay_pcap_pyshark(pcap_path, playback_speed)
            return
        if parser == "auto" and PcapReader is None and dpkt is not None:
            self.replay_pcap_dpkt(pcap_path, playback_speed)
            return
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

    def replay_pcap_dpkt(self, pcap_path: str, playback_speed: Optional[float] = None) -> None:
        if dpkt is None:
            raise RuntimeError(f"dpkt parser requested but unavailable: {DPKT_IMPORT_ERROR}")
        file_path = Path(pcap_path)
        if not file_path.exists():
            raise FileNotFoundError(file_path)
        previous = None
        speed = self.config.playback_speed if playback_speed is None else playback_speed
        with file_path.open("rb") as handle:
            reader = dpkt.pcap.Reader(handle)
            for packet_time, frame in reader:
                if speed and previous is not None:
                    wait = max(0.0, float(packet_time) - previous) / max(speed, 0.0001)
                    if wait:
                        time.sleep(min(wait, 1.5))
                context = self.build_context_from_dpkt_frame(bytes(frame), float(packet_time))
                if context is not None and self._allow_context(context):
                    self._process_context(context, packet=None, payload_override=self._payload_from_dpkt_frame(bytes(frame)))
                previous = float(packet_time)

    def replay_pcap_pyshark(self, pcap_path: str, playback_speed: Optional[float] = None) -> None:
        if pyshark is None:
            raise RuntimeError(f"pyshark parser requested but unavailable: {PYSHARK_IMPORT_ERROR}")
        file_path = Path(pcap_path)
        if not file_path.exists():
            raise FileNotFoundError(file_path)
        previous = None
        speed = self.config.playback_speed if playback_speed is None else playback_speed
        capture = pyshark.FileCapture(str(file_path), keep_packets=False)
        try:
            for packet in capture:
                packet_time = float(getattr(packet, "sniff_timestamp", time.time()) or time.time())
                if speed and previous is not None:
                    wait = max(0.0, packet_time - previous) / max(speed, 0.0001)
                    if wait:
                        time.sleep(min(wait, 1.5))
                payload = self.payload_from_pyshark_packet(packet, packet_time)
                if payload:
                    self.ingest_remote_context(payload)
                previous = packet_time
        finally:
            capture.close()

    def ingest_remote_raw_packet(self, payload: Dict[str, object]) -> Dict[str, object]:
        import base64

        encoded = str(payload.get("packet_base64") or payload.get("frame_base64") or "").strip()
        if not encoded:
            raise ValueError("packet_base64 is required for raw packet ingestion")
        raw_frame = base64.b64decode(encoded.encode("utf-8"), validate=False)
        timestamp = float(payload.get("timestamp") or time.time())
        context = self.build_context_from_raw_frame(raw_frame, timestamp, str(payload.get("parser") or ""))
        if context is None or not self._allow_context(context):
            return {"status": "ignored", "reason": "parser-or-filter", "sensor_id": payload.get("sensor_id", "")}
        self._process_context(context, packet=None, payload_override=self.extract_transport_payload(raw_frame))
        return {
            "status": "ingested",
            "session_id": context.session_id,
            "category": context.category,
            "sensor_id": payload.get("sensor_id", ""),
        }

    def build_context_from_raw_frame(self, raw_frame: bytes, timestamp: float, parser: str = "") -> Optional[PacketContext]:
        selected = (parser or self.config.packet_parser or "auto").lower()
        if selected in {"dpkt", "auto"} and dpkt is not None:
            context = self.build_context_from_dpkt_frame(raw_frame, timestamp)
            if context is not None:
                return context
        if Ether is not None:
            try:
                return self.build_context(Ether(raw_frame), timestamp)
            except Exception:
                return None
        return None

    def start_live_capture(self) -> None:
        if sniff is None:
            raise RuntimeError(f"Scapy is required for live capture: {SCAPY_IMPORT_ERROR}")
        self.capture_threads = [thread for thread in self.capture_threads if thread.is_alive()]
        if self.capture_threads:
            return
        self.last_capture_error = ""
        self.stop_event.clear()
        self.start_workers()
        configured = [iface for iface in self.config.interfaces if str(iface).strip()]
        if any(str(iface).strip().lower() in {"all", "*"} for iface in configured):
            interfaces = self.available_interfaces() or [None]
        else:
            interfaces = configured or [None]
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
        if self.stop_event.is_set():
            return
        try:
            self.packet_queue.put((packet, packet_time), timeout=2)
        except queue.Full:
            return

    def _worker_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                packet, packet_time = self.packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if self.stop_event.is_set():
                    return
                self.process_packet(packet, packet_time)
            except Exception:
                if not self.stop_event.is_set():
                    traceback.print_exc()
            finally:
                self.packet_queue.task_done()

    def _sniff_interface(self, iface: Optional[str]) -> None:
        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=iface,
                    store=False,
                    filter=self.config.bpf_filter or None,
                    prn=lambda packet: self.enqueue_packet(packet),
                    timeout=1,
                )
            except Exception as exc:
                self.last_capture_error = f"Capture failed on {iface or 'default adapter'}: {exc}"
                self.stop_event.set()
                break

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
        self._process_context(context, packet)

    def ingest_remote_context(self, payload: Dict[str, object]) -> Dict[str, object]:
        context = self.build_context_from_payload(payload)
        if not self._allow_context(context):
            return {"status": "ignored", "reason": "quick-filter", "session_id": context.session_id}
        raw_payload = b""
        payload_b64 = str(payload.get("payload_base64") or "").strip()
        if payload_b64:
            try:
                import base64

                raw_payload = base64.b64decode(payload_b64.encode("utf-8"), validate=False)
            except Exception:
                raw_payload = b""
        self._process_context(context, packet=None, payload_override=raw_payload[: self.config.stream_file_chunk_bytes])
        return {"status": "ingested", "session_id": context.session_id, "category": context.category}

    def _process_context(self, context: PacketContext, packet=None, payload_override: bytes = b"") -> None:
        with self.lock:
            self.packet_count += 1
            state = self.get_host_state(context.src_ip)
            self._decay_score(state, context.timestamp)
            self._update_state(state, context)
            self._update_session(context, packet, payload_override)
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
            findings.extend(self._detect_sequence_anomaly(state, context))
            findings.extend(self._detect_lstm_sequence_anomaly(state, context))
            findings.extend(self._detect_ml_anomaly(state, context))
            findings.extend(self._detect_protocol_activity(context))

            self._apply_findings(state, context, findings)
            self._persist_baseline_if_needed(state, context.timestamp)

    def build_context_from_payload(self, payload: Dict[str, object]) -> PacketContext:
        timestamp = float(payload.get("timestamp") or time.time())
        src_ip = str(payload.get("src_ip") or "").strip()
        dst_ip = str(payload.get("dst_ip") or "").strip()
        if not src_ip or not dst_ip:
            raise ValueError("src_ip and dst_ip are required for remote ingestion")
        src_port = int(payload.get("src_port") or 0)
        dst_port = int(payload.get("dst_port") or 0)
        transport = str(payload.get("transport") or "TCP").upper()
        category_map = {
            "HTTP": "HTTP",
            "HTTPS": "HTTPS",
            "TLS": "TLS",
            "DNS": "DNS",
            "MDNS": "mDNS",
            "FTP": "FTP",
            "SMB": "SMB",
            "RDP": "RDP",
            "LDAP": "LDAP",
            "KERBEROS": "KERBEROS",
            "P2P": "P2P",
            "IRC": "IRC",
            "TCP": "TCP",
            "UDP": "UDP",
            "IP": "IP",
        }
        category = category_map.get(str(payload.get("category") or transport).upper(), str(payload.get("category") or transport).upper())
        direction = str(payload.get("direction") or infer_direction(src_ip, dst_ip))
        private_pair = bool(payload.get("private_pair")) or (is_private_or_local(src_ip) and is_private_or_local(dst_ip))
        hostname = str(payload.get("hostname") or (dst_ip if private_pair else self.resolve_hostname(dst_ip))).strip() or dst_ip
        domain = str(payload.get("base_domain") or base_domain(hostname or dst_ip))
        geo = str(payload.get("geo") or self.geoip.lookup(dst_ip))
        protocol_tags = [str(item) for item in payload.get("protocol_tags", []) if item]
        protocol_details = dict(payload.get("protocol_details", {}) or {})
        dns_query = normalize_domain(str(payload.get("dns_query") or ""))
        http_url = str(payload.get("http_url") or "").strip()
        tls_sni = str(payload.get("tls_sni") or "").strip()
        if tls_sni and not hostname:
            hostname = tls_sni
            domain = base_domain(tls_sni)
        session_id = str(payload.get("session_id") or normalize_session_id(src_ip, src_port, dst_ip, dst_port, transport))
        trusted = bool(payload.get("trusted"))
        if not trusted:
            trusted = any(keyword in hostname.lower() for keyword in TRUSTED_HOST_KEYWORDS) or private_pair
        ioc_matches = self.intel.match([src_ip, dst_ip], [hostname, domain, dns_query, tls_sni])
        detail = str(payload.get("detail") or http_url or dns_query or protocol_details.get("command") or f"{src_port}->{dst_port}")
        context = PacketContext(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport=transport,
            category=category,
            detail=detail,
            packet_len=int(payload.get("packet_len") or len(str(payload.get("payload_preview") or "")) or 0),
            direction=direction,
            hostname=hostname,
            base_domain=domain,
            geo=geo,
            trusted=trusted,
            private_pair=private_pair,
            dns_query=dns_query,
            http_method=str(payload.get("http_method") or ""),
            http_url=http_url,
            http_host=str(payload.get("http_host") or hostname),
            http_user_agent=str(payload.get("http_user_agent") or ""),
            http_body_size=int(payload.get("http_body_size") or 0),
            http_query_string=str(payload.get("http_query_string") or ""),
            http_status=str(payload.get("http_status") or ""),
            http_content_type=str(payload.get("http_content_type") or ""),
            tls_version=str(payload.get("tls_version") or ""),
            tls_sni=tls_sni,
            tls_cert_subject=str(payload.get("tls_cert_subject") or ""),
            tls_cert_issuer=str(payload.get("tls_cert_issuer") or ""),
            tls_self_signed=bool(payload.get("tls_self_signed")),
            payload_preview=str(payload.get("payload_preview") or ""),
            os_guess=str(payload.get("os_guess") or fingerprint_os(int(payload.get("ttl") or 0), int(payload.get("tcp_window") or 0))),
            ttl=int(payload.get("ttl") or 0),
            tcp_window=int(payload.get("tcp_window") or 0),
            tcp_flags=int(payload.get("tcp_flags") or 0),
            tcp_seq=int(payload.get("tcp_seq") or 0),
            tcp_ack=int(payload.get("tcp_ack") or 0),
            tcp_payload_len=int(payload.get("tcp_payload_len") or 0),
            session_id=session_id,
            protocol_tags=protocol_tags,
            protocol_details=protocol_details,
            ioc_matches=ioc_matches,
            risk_score=int(payload.get("risk_score") or 0),
            risk_factors=[str(item) for item in payload.get("risk_factors", []) if item],
        )
        return context

    def _inet_to_text(self, value: bytes) -> str:
        if len(value) == 4:
            return socket.inet_ntop(socket.AF_INET, value)
        if len(value) == 16:
            return socket.inet_ntop(socket.AF_INET6, value)
        return ""

    def _dpkt_ip_packet(self, raw_frame: bytes):
        if dpkt is None:
            return None
        try:
            eth = dpkt.ethernet.Ethernet(raw_frame)
            packet = eth.data
        except Exception:
            packet = None
        if packet is not None and packet.__class__.__name__ in {"IP", "IP6"}:
            return packet
        try:
            packet = dpkt.ip.IP(raw_frame)
            return packet
        except Exception:
            return None

    def _payload_from_dpkt_frame(self, raw_frame: bytes) -> bytes:
        packet = self._dpkt_ip_packet(raw_frame)
        if packet is None:
            return b""
        transport = getattr(packet, "data", None)
        data = getattr(transport, "data", b"")
        return bytes(data or b"")

    def extract_transport_payload(self, raw_frame: bytes) -> bytes:
        if dpkt is not None:
            payload = self._payload_from_dpkt_frame(raw_frame)
            if payload:
                return payload[: self.config.stream_file_chunk_bytes]
        if Ether is not None and Raw is not None:
            try:
                packet = Ether(raw_frame)
                if packet.haslayer(Raw):
                    return bytes(packet[Raw].load[: self.config.stream_file_chunk_bytes])
            except Exception:
                return b""
        return b""

    def build_context_from_dpkt_frame(self, raw_frame: bytes, timestamp: Optional[float] = None) -> Optional[PacketContext]:
        if dpkt is None:
            return None
        packet = self._dpkt_ip_packet(raw_frame)
        if packet is None:
            return None
        src_ip = self._inet_to_text(getattr(packet, "src", b""))
        dst_ip = self._inet_to_text(getattr(packet, "dst", b""))
        if not src_ip or not dst_ip:
            return None
        transport_packet = getattr(packet, "data", None)
        transport = "IP"
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        tcp_seq = 0
        tcp_ack = 0
        tcp_window = 0
        payload = bytes(getattr(transport_packet, "data", b"") or b"")
        if isinstance(transport_packet, dpkt.tcp.TCP):
            transport = "TCP"
            src_port = int(transport_packet.sport)
            dst_port = int(transport_packet.dport)
            tcp_flags = int(transport_packet.flags)
            tcp_seq = int(transport_packet.seq)
            tcp_ack = int(transport_packet.ack)
            tcp_window = int(transport_packet.win)
        elif isinstance(transport_packet, dpkt.udp.UDP):
            transport = "UDP"
            src_port = int(transport_packet.sport)
            dst_port = int(transport_packet.dport)
        direction = infer_direction(src_ip, dst_ip)
        category = self._category_from_ports(transport, src_port, dst_port, payload)
        protocol_details = self._dissect_protocol_payload(category, payload)
        http_info = parse_http_payload(payload)
        dns_query = ""
        if category in {"DNS", "mDNS"} and payload:
            try:
                dns = dpkt.dns.DNS(payload)
                if dns.qd:
                    dns_query = normalize_domain(str(dns.qd[0].name))
            except Exception:
                dns_query = ""
        tls_hello = parse_tls_client_hello(payload)
        tls_cert = parse_tls_certificate(payload)
        hostname = ""
        if http_info.get("host"):
            hostname = str(http_info.get("host") or "")
        elif tls_hello.get("sni"):
            hostname = str(tls_hello.get("sni") or "")
        elif dns_query:
            hostname = dns_query
        return self.build_context_from_payload(
            {
                "timestamp": float(timestamp or time.time()),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "transport": transport,
                "category": category,
                "direction": direction,
                "hostname": hostname,
                "dns_query": dns_query,
                "http_method": str(http_info.get("method") or ""),
                "http_url": str(http_info.get("url") or ""),
                "http_host": str(http_info.get("host") or ""),
                "http_user_agent": str(http_info.get("user_agent") or ""),
                "http_body_size": int(http_info.get("body_size") or 0),
                "http_query_string": str(http_info.get("query_string") or ""),
                "http_status": str(http_info.get("status") or ""),
                "http_content_type": str(http_info.get("content_type") or ""),
                "tls_version": str(tls_hello.get("version") or tls_cert.get("version") or ""),
                "tls_sni": str(tls_hello.get("sni") or ""),
                "tls_cert_subject": str(tls_cert.get("subject") or ""),
                "tls_cert_issuer": str(tls_cert.get("issuer") or ""),
                "tls_self_signed": bool(tls_cert.get("self_signed")),
                "packet_len": len(raw_frame),
                "payload_preview": safe_decode(payload[:512]),
                "ttl": int(getattr(packet, "ttl", getattr(packet, "hlim", 0)) or 0),
                "tcp_window": tcp_window,
                "tcp_flags": tcp_flags,
                "tcp_seq": tcp_seq,
                "tcp_ack": tcp_ack,
                "tcp_payload_len": len(payload),
                "protocol_details": protocol_details,
            }
        )

    def payload_from_pyshark_packet(self, packet, packet_time: Optional[float] = None) -> Dict[str, object]:
        def layer_value(layer_name: str, field_name: str, default: str = "") -> str:
            layer = getattr(packet, layer_name, None)
            if layer is None:
                return default
            return str(getattr(layer, field_name, default) or default)

        src_ip = layer_value("ip", "src") or layer_value("ipv6", "src")
        dst_ip = layer_value("ip", "dst") or layer_value("ipv6", "dst")
        if not src_ip or not dst_ip:
            return {}
        transport = "TCP" if hasattr(packet, "tcp") else "UDP" if hasattr(packet, "udp") else "IP"
        src_port = int(layer_value("tcp", "srcport", "0") or layer_value("udp", "srcport", "0") or 0)
        dst_port = int(layer_value("tcp", "dstport", "0") or layer_value("udp", "dstport", "0") or 0)
        category = layer_value("frame", "protocols", "").split(":")[-1].upper()
        if category in {"DATA", ""}:
            category = self._category_from_ports(transport, src_port, dst_port, b"")
        return {
            "timestamp": float(packet_time or time.time()),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "transport": transport,
            "category": category,
            "direction": infer_direction(src_ip, dst_ip),
            "hostname": layer_value("dns", "qry_name") or layer_value("tls", "handshake_extensions_server_name"),
            "dns_query": layer_value("dns", "qry_name"),
            "http_method": layer_value("http", "request_method"),
            "http_url": layer_value("http", "request_uri"),
            "http_user_agent": layer_value("http", "user_agent"),
            "http_status": layer_value("http", "response_code"),
            "tls_sni": layer_value("tls", "handshake_extensions_server_name"),
            "packet_len": int(getattr(packet, "length", 0) or layer_value("frame", "len", "0") or 0),
            "payload_preview": str(packet)[:512],
        }

    def _category_from_ports(self, transport: str, src_port: int, dst_port: int, payload: bytes) -> str:
        ports = {src_port, dst_port}
        if ports & DNS_PORTS:
            return "DNS"
        if MDNS_PORT in ports:
            return "mDNS"
        if ports & HTTP_PORTS or parse_http_payload(payload).get("is_http"):
            return "HTTP"
        if ports & HTTPS_PORTS:
            return "TLS"
        if ports & FTP_PORTS:
            return "FTP"
        if ports & SMB_PORTS:
            return "SMB"
        if ports & RDP_PORTS:
            return "RDP"
        if ports & LDAP_PORTS:
            return "LDAP"
        if ports & KERBEROS_PORTS:
            return "KERBEROS"
        if ports & IRC_PORTS:
            return "IRC"
        if ports & P2P_PORTS:
            return "P2P"
        return transport

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
        tcp_seq = 0
        tcp_ack = 0
        payload = b""
        ttl = int(getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", 0)) or 0)

        if TCP is not None and packet.haslayer(TCP):
            transport = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            tcp_flags = int(packet[TCP].flags)
            tcp_window = int(packet[TCP].window)
            tcp_seq = int(getattr(packet[TCP], "seq", 0) or 0)
            tcp_ack = int(getattr(packet[TCP], "ack", 0) or 0)
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
        http_status = ""
        http_content_type = ""
        tls_version = ""
        tls_sni = ""
        tls_cert_subject = ""
        tls_cert_issuer = ""
        tls_self_signed = False
        protocol_details: Dict[str, object] = {}

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
                http_status = str(http_info.get("status", ""))
                http_content_type = str(http_info.get("content_type", ""))
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
        if dst_port in FTP_PORTS or src_port in FTP_PORTS:
            protocol_tags.append("ftp")
            if category == "TCP":
                category = "FTP"
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

        protocol_details = self._dissect_protocol_payload(category, payload)
        if category == "FTP" and protocol_details.get("command"):
            detail = str(protocol_details.get("command"))
            if protocol_details.get("argument"):
                detail = f"{detail} {protocol_details.get('argument')}"

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
            http_status=http_status,
            http_content_type=http_content_type,
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
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_payload_len=len(payload),
            session_id=session_id,
            protocol_tags=protocol_tags,
            protocol_details=protocol_details,
            ioc_matches=ioc_matches,
        )
        return context

    def _dissect_protocol_payload(self, category: str, payload: bytes) -> Dict[str, object]:
        if not payload:
            return {}
        if category == "FTP":
            return parse_ftp_payload(payload)
        if category == "SMB":
            return parse_smb_payload(payload)
        if category == "RDP":
            return parse_rdp_payload(payload)
        if category == "LDAP":
            return parse_ldap_payload(payload)
        if category == "KERBEROS":
            return parse_kerberos_payload(payload)
        return {}

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

        interarrival = state.interarrival_samples[-1] if state.interarrival_samples else 0.0
        packet_rate_30s = len(state.packet_times) / 30.0
        dns_rate = len(state.dns_times) / max(1.0, float(self.config.dns_frequency_window))
        outbound_bytes = sum_bytes(state.outbound_bytes)
        port_seen = max(1, state.port_counts[context.dst_port])
        protocol_seen = max(1, state.protocol_counts[context.category])
        port_rarity = 1.0 / float(port_seen)
        protocol_rarity = 1.0 / float(protocol_seen)
        entropy_source = context.dns_query or context.hostname or context.payload_preview
        feature_vector = [
            float(context.packet_len),
            float(context.dst_port),
            float(transport_code(context.category)),
            float(context.ttl or 0),
            float(context.http_body_size or 0),
            float(interarrival),
            float(packet_rate_30s),
            float(dns_rate),
            float(outbound_bytes),
            float(port_rarity),
            float(protocol_rarity),
            float(shannon_entropy(entropy_source[:160])),
            float(direction_code(context.direction)),
            float(len(context.ioc_matches)),
        ]
        state.feature_samples.append(feature_vector)
        self.ml_features.append(feature_vector)

        sequence_token = self._sequence_token(context)
        previous_token = state.last_sequence_token
        if previous_token and sequence_token:
            previous_total = int(state.transition_totals.get(previous_token, 0))
            pair_seen = int(state.transition_counts[previous_token].get(sequence_token, 0))
            context.protocol_details["_sequence_transition"] = {
                "previous": previous_token,
                "current": sequence_token,
                "previous_total": previous_total,
                "pair_seen": pair_seen,
            }
            state.transition_counts[previous_token][sequence_token] += 1
            state.transition_totals[previous_token] += 1
        if sequence_token:
            self._update_lstm_sequence(state, context, sequence_token)
            state.last_sequence_token = sequence_token

    def _update_lstm_sequence(self, state: HostState, context: PacketContext, sequence_token: str) -> None:
        if not self.config.lstm_enabled:
            state.sequence_tokens.append(sequence_token)
            self.sequence_tokens_global.append(sequence_token)
            return

        previous_tokens = list(state.sequence_tokens)
        if len(previous_tokens) >= self.config.lstm_sequence_length:
            probability = self.lstm_model.probability(previous_tokens, sequence_token, self.config.lstm_sequence_length)
            if probability is not None:
                context.protocol_details["_lstm_prediction"] = {
                    "token": sequence_token,
                    "probability": probability,
                    "sequence_length": self.config.lstm_sequence_length,
                }

        state.sequence_tokens.append(sequence_token)
        self.sequence_tokens_global.append(sequence_token)
        if not self.lstm_model.available:
            return
        if len(self.sequence_tokens_global) < self.config.lstm_min_samples:
            return
        if len(self.sequence_tokens_global) - self.lstm_model.last_train_count < max(50, self.config.lstm_sequence_length * 4):
            return
        try:
            self.lstm_model.train(
                list(self.sequence_tokens_global),
                sequence_length=self.config.lstm_sequence_length,
                epochs=2,
            )
        except Exception as exc:
            self.lstm_model.error = str(exc)

    def _update_session(self, context: PacketContext, packet=None, payload_override: bytes = b"") -> None:
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
        visible_details = {key: value for key, value in context.protocol_details.items() if not str(key).startswith("_")}
        if visible_details:
            merged = dict(session.protocol_details.get(context.category, {}))
            merged.update(visible_details)
            session.protocol_details[context.category] = merged
            session.last_protocol_detail = f"{context.category}: {', '.join(f'{key}={value}' for key, value in merged.items() if value)[:180]}"

        payload = payload_override or b""
        if not payload and packet is not None and Raw is not None and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load[: self.config.stream_file_chunk_bytes])

        role = self._stream_role(session, context)
        context.stream_direction = role
        if payload:
            reassembled = self._reassemble_tcp_payload(session, context, role, payload)
            if context.transport != "TCP":
                reassembled = payload
            if reassembled:
                self._append_stream_chunk(session, role, reassembled)
                self._continue_pending_artifact(session, role, reassembled, context.timestamp)
                self._update_http_reconstruction(session, context, reassembled, role)
                self._update_ftp_reconstruction(session, context, reassembled, role)

        if context.http_url:
            session.last_request_url = context.http_url
        if context.http_status:
            session.last_http_status = context.http_status
        session.conversation_summary = self._build_conversation_summary(session)

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

    def _sequence_token(self, context: PacketContext) -> str:
        port = context.dst_port if context.direction != "inbound" else context.src_port
        service = SERVICE_PORT_LABELS.get(port)
        if not service:
            if port <= 0:
                service = "unknown"
            elif port < 1024:
                service = f"priv-{port}"
            elif port < 49152:
                service = "registered"
            else:
                service = "ephemeral"
        token = f"{context.direction}:{context.category.lower()}:{service}"
        if context.http_method:
            token = f"{token}:{context.http_method.upper()}"
        return token

    def _stream_role(self, session: SessionRecord, context: PacketContext) -> str:
        if (context.src_ip, context.src_port) == (session.src_ip, session.src_port):
            return "client"
        return "server"

    def _stream_file_path(self, session: SessionRecord, role: str) -> Path:
        safe_id = safe_path_fragment(session.session_id)
        suffix = "c2s" if role == "client" else "s2c"
        return Path(self.config.session_dir) / f"{safe_id}-{suffix}.bin"

    def _reassemble_tcp_payload(
        self,
        session: SessionRecord,
        context: PacketContext,
        role: str,
        payload: bytes,
    ) -> bytes:
        if context.transport != "TCP":
            return payload
        state = self.reassembly_buffers[(session.session_id, role)]
        data_seq = context.tcp_seq + (1 if context.tcp_flags & 0x02 else 0)
        if state.next_seq is None:
            state.next_seq = data_seq
        if not payload:
            if context.tcp_flags & 0x02 and state.next_seq == data_seq:
                state.next_seq = data_seq
            self._snapshot_reassembly_state(session, role, state)
            return b""
        if data_seq > (state.next_seq or data_seq):
            state.out_of_order += 1
        if data_seq < (state.next_seq or data_seq):
            overlap = (state.next_seq or data_seq) - data_seq
            if overlap >= len(payload):
                state.overlaps += 1
                self._snapshot_reassembly_state(session, role, state)
                return b""
            payload = payload[overlap:]
            data_seq = state.next_seq or data_seq
            state.overlaps += 1

        existing = state.fragments.get(data_seq)
        if existing is None or len(payload) > len(existing):
            state.fragments[data_seq] = payload
        else:
            state.overlaps += 1

        if len(state.fragments) > self.config.reassembly_max_fragments:
            for sequence in sorted(state.fragments)[: max(1, len(state.fragments) - self.config.reassembly_max_fragments)]:
                if sequence != state.next_seq:
                    state.fragments.pop(sequence, None)

        contiguous = bytearray()
        while state.next_seq is not None and state.next_seq in state.fragments:
            chunk = state.fragments.pop(state.next_seq)
            contiguous.extend(chunk)
            state.next_seq += len(chunk)
            state.contiguous_bytes += len(chunk)

        self._snapshot_reassembly_state(session, role, state)
        return bytes(contiguous)

    def _snapshot_reassembly_state(self, session: SessionRecord, role: str, state: ReassemblyBuffer) -> None:
        session.reassembly[role] = {
            "next_seq": state.next_seq or 0,
            "buffered_fragments": len(state.fragments),
            "out_of_order": state.out_of_order,
            "overlaps": state.overlaps,
            "contiguous_bytes": state.contiguous_bytes,
        }

    def _append_stream_chunk(self, session: SessionRecord, role: str, payload: bytes) -> None:
        path = self._stream_file_path(session, role)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as handle:
            handle.write(payload)

        preview_text = safe_decode(payload).replace("\r", " ").replace("\n", " ").strip()
        if role == "client":
            session.client_payload_bytes += len(payload)
            session.client_stream_path = str(path)
            combined = f"{session.reconstructed_client_preview} {preview_text}".strip()
            session.reconstructed_client_preview = combined[-self.config.stream_preview_chars:]
        else:
            session.server_payload_bytes += len(payload)
            session.server_stream_path = str(path)
            combined = f"{session.reconstructed_server_preview} {preview_text}".strip()
            session.reconstructed_server_preview = combined[-self.config.stream_preview_chars:]

    def _update_http_reconstruction(self, session: SessionRecord, context: PacketContext, payload: bytes, role: str) -> None:
        http_info = parse_http_payload(payload)
        if not http_info.get("is_http"):
            return

        if http_info.get("is_response"):
            session.response_count += 1
            session.last_http_status = str(http_info.get("status", "")) or session.last_http_status
            self._start_response_artifact(session, context, payload, http_info, role)
            return

        session.request_count += 1
        session.last_request_url = str(http_info.get("url", "")) or session.last_request_url
        if FILE_HINT_RE.search(session.last_request_url):
            self._record_artifact_hint(session, context)

    def _update_ftp_reconstruction(self, session: SessionRecord, context: PacketContext, payload: bytes, role: str) -> None:
        if context.category != "FTP":
            return
        ftp_info = parse_ftp_payload(payload)
        if not ftp_info:
            ftp_info = context.protocol_details
        if not ftp_info:
            self._append_ftp_transfer_chunk(session, context, payload)
            return
        if ftp_info.get("command"):
            session.request_count += 1
            session.last_protocol_detail = f"FTP: {ftp_info.get('command')} {ftp_info.get('argument', '')}".strip()
        if ftp_info.get("status_code"):
            session.response_count += 1
        file_name = str(ftp_info.get("file_name", "") or "")
        command = str(ftp_info.get("command", "") or "")
        if file_name and command in {"RETR", "STOR", "RNFR", "RNTO"}:
            self._record_ftp_artifact_hint(session, context, file_name, "complete")
        if file_name and command in {"RETR", "STOR"} and role == "client":
            self._remember_ftp_transfer(session, context, file_name, command)
        if not ftp_info.get("command") and not ftp_info.get("status_code"):
            self._append_ftp_transfer_chunk(session, context, payload)

    def _record_artifact_hint(self, session: SessionRecord, context: PacketContext) -> None:
        self._extract_http_artifact(context)
        candidate = {
            "timestamp": context.timestamp,
            "file_name": Path(urlparse(context.http_url).path).name or "download.bin",
            "file_path": "",
            "content_type": "",
            "source_url": context.http_url,
            "bytes_written": 0,
            "status": "hint",
        }
        self._merge_artifact(session, candidate)
        session.extracted_artifact = context.http_url

    def _record_ftp_artifact_hint(self, session: SessionRecord, context: PacketContext, file_name: str, operation: str) -> None:
        candidate = {
            "timestamp": context.timestamp,
            "file_name": safe_path_fragment(file_name or "ftp-transfer.bin"),
            "file_path": "",
            "content_type": "application/octet-stream",
            "source_url": f"ftp://{context.hostname or context.dst_ip}/{safe_path_fragment(file_name or 'ftp-transfer.bin')}",
            "bytes_written": 0,
            "status": operation.lower(),
            "protocol": "FTP",
        }
        self._merge_artifact(session, candidate)
        session.extracted_artifact = candidate["source_url"]

    def _remember_ftp_transfer(self, session: SessionRecord, context: PacketContext, file_name: str, command: str) -> None:
        artifact_dir = Path(self.config.artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        safe_name = safe_path_fragment(file_name or "ftp-transfer.bin")
        pair_key = tuple(sorted((context.src_ip, context.dst_ip)))
        if pair_key in self.pending_ftp_transfers and self.pending_ftp_transfers[pair_key].get("file_name") != safe_name:
            self.pending_ftp_transfers.pop(pair_key, None)
        artifact_path = artifact_dir / f"ftp-{safe_path_fragment(session.session_id)}-{safe_name}"
        if artifact_path.exists():
            artifact_path = artifact_dir / f"ftp-{int(context.timestamp)}-{safe_path_fragment(session.session_id)}-{safe_name}"
        operation = "download" if command == "RETR" else "upload"
        self.pending_ftp_transfers[pair_key] = {
            "file_name": safe_name,
            "path": str(artifact_path),
            "source_url": f"ftp://{context.hostname or context.dst_ip}/{safe_name}",
            "operation": operation,
            "timestamp": context.timestamp,
            "bytes_written": 0,
        }

    def _append_ftp_transfer_chunk(self, session: SessionRecord, context: PacketContext, payload: bytes) -> None:
        if not payload:
            return
        pair_key = tuple(sorted((context.src_ip, context.dst_ip)))
        transfer = self.pending_ftp_transfers.get(pair_key)
        if not transfer:
            return
        if context.timestamp - float(transfer.get("timestamp", 0)) > FTP_TRANSFER_TIMEOUT:
            self.pending_ftp_transfers.pop(pair_key, None)
            return

        path = Path(str(transfer["path"]))
        remaining = max(0, self.config.artifact_max_bytes - int(transfer.get("bytes_written", 0)))
        if remaining <= 0:
            self.pending_ftp_transfers.pop(pair_key, None)
            return
        chunk = payload[:remaining]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as handle:
            handle.write(chunk)

        transfer["timestamp"] = context.timestamp
        transfer["bytes_written"] = int(transfer.get("bytes_written", 0)) + len(chunk)
        complete = bool(context.tcp_flags & 0x01 or context.tcp_flags & 0x04) or transfer["bytes_written"] >= self.config.artifact_max_bytes
        self._merge_artifact(
            session,
            {
                "timestamp": context.timestamp,
                "file_name": str(transfer["file_name"]),
                "file_path": str(path),
                "content_type": "application/octet-stream",
                "source_url": str(transfer["source_url"]),
                "bytes_written": int(transfer["bytes_written"]),
                "status": "complete" if complete else "extracting",
                "protocol": "FTP",
                "operation": str(transfer.get("operation", "transfer")),
            },
        )
        session.extracted_artifact = str(path)
        if complete:
            self.pending_ftp_transfers.pop(pair_key, None)

    def _merge_artifact(self, session: SessionRecord, artifact: Dict[str, object]) -> None:
        for existing in session.artifacts:
            if existing.get("file_path") and existing.get("file_path") == artifact.get("file_path"):
                existing.update(artifact)
                return
            if existing.get("source_url") and existing.get("source_url") == artifact.get("source_url") and existing.get("file_name") == artifact.get("file_name"):
                existing.update(artifact)
                return
        session.artifacts.append(artifact)

    def _split_http_body(self, payload: bytes) -> Tuple[bytes, bytes]:
        for separator in (b"\r\n\r\n", b"\n\n"):
            if separator in payload:
                return payload.split(separator, 1)
        return payload, b""

    def _guess_artifact_filename(
        self,
        session: SessionRecord,
        context: PacketContext,
        headers: Dict[str, str],
    ) -> str:
        disposition = headers.get("content-disposition", "")
        match = re.search(r'filename="?([^";]+)"?', disposition, re.IGNORECASE)
        if match:
            return safe_path_fragment(match.group(1))
        url_candidate = session.last_request_url or context.http_url
        if url_candidate:
            name = Path(urlparse(url_candidate).path).name
            if name:
                return safe_path_fragment(name)
        content_type = headers.get("content-type", "") or context.http_content_type
        extension = ".bin"
        if "pdf" in content_type:
            extension = ".pdf"
        elif "zip" in content_type:
            extension = ".zip"
        elif "json" in content_type:
            extension = ".json"
        elif "html" in content_type:
            extension = ".html"
        return f"{safe_path_fragment(session.session_id)}{extension}"

    def _start_response_artifact(
        self,
        session: SessionRecord,
        context: PacketContext,
        payload: bytes,
        http_info: Dict[str, object],
        role: str,
    ) -> None:
        if role != "server":
            return
        headers = {str(key).lower(): str(value) for key, value in dict(http_info.get("headers", {})).items()}
        content_type = headers.get("content-type", "")
        disposition = headers.get("content-disposition", "")
        interesting = disposition or any(content_type.lower().startswith(prefix) for prefix in DOWNLOAD_CONTENT_TYPES)
        if not interesting and not FILE_HINT_RE.search(session.last_request_url or context.http_url):
            return

        _, body = self._split_http_body(payload)
        artifact_name = self._guess_artifact_filename(session, context, headers)
        path = Path(self.config.artifact_dir) / artifact_name
        if path.exists():
            path = Path(self.config.artifact_dir) / f"{safe_path_fragment(session.session_id)}-{artifact_name}"
        max_bytes = self.config.artifact_max_bytes
        body = body[:max_bytes]
        with path.open("wb") as handle:
            handle.write(body)

        content_length = headers.get("content-length", "")
        remaining = 0
        try:
            total_expected = int(content_length)
            remaining = max(0, total_expected - len(body))
        except Exception:
            remaining = 0

        artifact = {
            "timestamp": context.timestamp,
            "file_name": path.name,
            "file_path": str(path),
            "content_type": content_type,
            "source_url": session.last_request_url or context.http_url,
            "bytes_written": len(body),
            "status": "extracting" if remaining > 0 else "complete",
        }
        self._merge_artifact(session, artifact)
        session.extracted_artifact = str(path)
        if remaining > 0:
            self.pending_artifacts[session.session_id] = {
                "path": str(path),
                "remaining": remaining,
                "role": role,
                "bytes_written": len(body),
                "timestamp": context.timestamp,
            }

    def _continue_pending_artifact(self, session: SessionRecord, role: str, payload: bytes, timestamp: float) -> None:
        pending = self.pending_artifacts.get(session.session_id)
        if not pending or pending.get("role") != role:
            return
        if pending["remaining"] <= 0:
            self.pending_artifacts.pop(session.session_id, None)
            return
        chunk = payload[: min(len(payload), int(pending["remaining"]), self.config.artifact_max_bytes)]
        if not chunk:
            return
        path = Path(str(pending["path"]))
        with path.open("ab") as handle:
            handle.write(chunk)
        pending["remaining"] = max(0, int(pending["remaining"]) - len(chunk))
        pending["bytes_written"] = int(pending["bytes_written"]) + len(chunk)
        status = "complete" if pending["remaining"] <= 0 else "extracting"
        self._merge_artifact(
            session,
            {
                "timestamp": timestamp,
                "file_name": path.name,
                "file_path": str(path),
                "bytes_written": pending["bytes_written"],
                "status": status,
            },
        )
        if pending["remaining"] <= 0:
            self.pending_artifacts.pop(session.session_id, None)

    def _build_conversation_summary(self, session: SessionRecord) -> str:
        parts = []
        if session.last_request_url:
            parts.append(f"request {session.last_request_url}")
        if session.last_http_status:
            parts.append(f"response {session.last_http_status}")
        if session.last_protocol_detail:
            parts.append(session.last_protocol_detail)
        if session.artifacts:
            parts.append(f"artifacts {len(session.artifacts)}")
        if not parts:
            parts.append(f"{session.packet_count} packets")
        return " | ".join(parts)

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

    def _detect_sequence_anomaly(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        if not self.config.sequence_model_enabled or not state.snapshot.baseline_ready:
            return []
        transition = dict(context.protocol_details.get("_sequence_transition", {}) or {})
        previous = str(transition.get("previous") or "")
        current = str(transition.get("current") or "")
        previous_total = int(transition.get("previous_total") or 0)
        pair_seen = int(transition.get("pair_seen") or 0)
        if not previous or not current or previous_total < self.config.sequence_min_transitions:
            return []

        probability = (pair_seen / previous_total) if previous_total else 0.0
        benign_web = (
            context.trusted
            and context.category in {"HTTP", "HTTPS", "TLS", "DNS"}
            and context.dst_port in KNOWN_SERVICE_PORTS
        )
        if pair_seen > 0 and probability >= self.config.sequence_probability_floor:
            return []
        if benign_web and pair_seen > 0:
            return []

        severity = "MEDIUM" if (not context.trusted or context.ioc_matches or context.dst_port not in KNOWN_SERVICE_PORTS) else "LOW"
        score_delta = 3 if severity == "MEDIUM" else 1
        return [
            DetectionFinding(
                title="Sequence anomaly model deviation",
                severity=severity,
                classification="Machine learning anomaly",
                score_delta=score_delta,
                reasons=[
                    f"Learned sequence model rarely transitions from {previous} to {current}.",
                    f"Observed transition frequency was {pair_seen}/{previous_total} ({probability:.3f}) for the host baseline.",
                ],
                action="Review the surrounding session, recent destinations, and companion detections to validate whether the communication pattern is expected.",
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                dedupe_key=f"ml-sequence:{context.src_ip}:{previous}:{current}",
                cooldown=900,
            )
        ]

    def _detect_lstm_sequence_anomaly(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        if not self.config.lstm_enabled or not state.snapshot.baseline_ready:
            return []
        prediction = dict(context.protocol_details.get("_lstm_prediction", {}) or {})
        if not prediction:
            return []
        probability = float(prediction.get("probability") or 1.0)
        token = str(prediction.get("token") or "")
        if probability >= self.config.lstm_anomaly_threshold:
            return []
        if context.trusted and context.dst_port in KNOWN_SERVICE_PORTS and not context.ioc_matches:
            return []
        severity = "HIGH" if context.ioc_matches or context.dst_port not in KNOWN_SERVICE_PORTS else "MEDIUM"
        return [
            DetectionFinding(
                title="LSTM sequence anomaly",
                severity=severity,
                classification="Machine learning anomaly",
                score_delta=5 if severity == "HIGH" else 3,
                reasons=[
                    f"TensorFlow/Keras LSTM model assigned probability {probability:.4f} to sequence token {token}.",
                    f"The configured anomaly threshold is {self.config.lstm_anomaly_threshold:.4f}.",
                ],
                action="Pivot into the reconstructed session and compare this host sequence against known application behavior.",
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                dedupe_key=f"ml-lstm:{context.src_ip}:{token}",
                cooldown=900,
            )
        ]

    def _detect_ml_anomaly(self, state: HostState, context: PacketContext) -> List[DetectionFinding]:
        trusted_destination = any(keyword in (context.hostname or "").lower() for keyword in TRUSTED_HOST_KEYWORDS)
        standard_port = context.dst_port in {
            53, 80, 123, 443, 445, 636, 8443, 3389, 5222, 5223, 5228, 8080, 8883,
        }
        if (
            not self.config.ml_enabled
            or IsolationForest is None
            or len(self.ml_features) < self.config.ml_min_global_samples
            or not state.snapshot.baseline_ready
            or len(state.feature_samples) < self.config.ml_min_host_samples
            or context.private_pair
        ):
            return []
        if trusted_destination and standard_port and context.category in {"TCP", "UDP", "HTTP", "HTTPS", "TLS"}:
            return []
        if self.ml_model is None or len(self.ml_features) - self.ml_last_train_count >= 100:
            self.ml_model = IsolationForest(contamination=0.015, random_state=42)
            self.ml_model.fit(list(self.ml_features))
            self.ml_last_train_count = len(self.ml_features)
        sample = list(state.feature_samples)[-1] if state.feature_samples else None
        if sample is None:
            return []
        prediction = int(self.ml_model.predict([sample])[0])
        anomaly_score = float(self.ml_model.decision_function([sample])[0])
        suspicious_port = not standard_port
        if prediction != -1 or anomaly_score > -0.08 or (trusted_destination and not suspicious_port):
            return []
        return [
            DetectionFinding(
                title="ML traffic outlier",
                severity="LOW" if suspicious_port else "MEDIUM",
                classification="Machine learning anomaly",
                score_delta=2 if suspicious_port else 1,
                reasons=[
                    "Isolation Forest marked the latest packet feature vector as a low-frequency deviation against learned traffic patterns.",
                    f"Features: size={context.packet_len}, port={context.dst_port}, ttl={context.ttl}, interarrival={sample[5]:.3f}, packet_rate={sample[6]:.2f}/s, anomaly_score={anomaly_score:.3f}.",
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
        ftp_details = context.protocol_details if context.category == "FTP" else {}
        if context.category == "FTP" and ftp_details.get("command") == "STOR":
            findings.append(
                DetectionFinding(
                    title="FTP upload command observed",
                    severity="MEDIUM",
                    classification="Protocol dissection",
                    score_delta=2,
                    reasons=[f"FTP STOR targeted {ftp_details.get('file_name') or ftp_details.get('argument') or 'a remote file'}."],
                    action="Validate whether plaintext FTP uploads are expected and review the transferred artifact.",
                    mitre_technique="T1048",
                    mitre_tactic="Exfiltration",
                    dedupe_key=f"ftp-stor:{context.session_id}:{ftp_details.get('file_name', '')}",
                    cooldown=1800,
                )
            )
        if context.category == "FTP" and ftp_details.get("command") == "RETR":
            findings.append(
                DetectionFinding(
                    title="FTP retrieval command observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=[f"FTP RETR requested {ftp_details.get('file_name') or ftp_details.get('argument') or 'a remote file'}."],
                    action="Use this as transfer context while investigating staging or tool retrieval.",
                    mitre_technique="T1105",
                    mitre_tactic="Command and Control",
                    dedupe_key=f"ftp-retr:{context.session_id}:{ftp_details.get('file_name', '')}",
                    cooldown=1800,
                )
            )
        smb_details = context.protocol_details if context.category == "SMB" else {}
        if context.category == "SMB" and (
            "NTLMSSP" in context.payload_preview.upper() or smb_details.get("auth") == "NTLMSSP"
        ):
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
        if context.category == "SMB" and smb_details.get("shares"):
            findings.append(
                DetectionFinding(
                    title="SMB share access observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=[f"SMB referenced share paths: {', '.join(smb_details.get('shares', [])[:3])}."],
                    action="Use this as asset and file-share context while investigating lateral movement or staging.",
                    mitre_technique="T1021",
                    mitre_tactic="Lateral Movement",
                    dedupe_key=f"smb-share:{context.session_id}",
                    cooldown=1800,
                )
            )
        rdp_details = context.protocol_details if context.category == "RDP" else {}
        if context.category == "RDP" and (
            "COOKIE: MSTSHASH" in context.payload_preview.upper() or rdp_details.get("stage") == "client-negotiation"
        ):
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
        if context.category == "RDP" and rdp_details.get("virtual_channels"):
            findings.append(
                DetectionFinding(
                    title="RDP virtual channels observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=[f"RDP virtual channels included {', '.join(rdp_details.get('virtual_channels', []))}."],
                    action="Use this to understand remote session capabilities during a host investigation.",
                    mitre_technique="T1021",
                    mitre_tactic="Lateral Movement",
                    dedupe_key=f"rdp-channels:{context.session_id}",
                    cooldown=1800,
                )
            )
        ldap_details = context.protocol_details if context.category == "LDAP" else {}
        if context.category == "LDAP" and ldap_details.get("simple_bind"):
            findings.append(
                DetectionFinding(
                    title="LDAP simple bind observed",
                    severity="MEDIUM",
                    classification="Protocol dissection",
                    score_delta=3,
                    reasons=["LDAP payload markers suggest a simple bind, which may expose credentials on plaintext LDAP."],
                    action="Prefer LDAPS where possible and validate whether this bind was expected for the client and directory service.",
                    mitre_technique="T1557",
                    mitre_tactic="Credential Access",
                    dedupe_key=f"ldap-simple-bind:{context.session_id}",
                    cooldown=1800,
                )
            )
        if context.category == "LDAP" and ldap_details.get("distinguished_names"):
            findings.append(
                DetectionFinding(
                    title="LDAP directory query context observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=[f"LDAP referenced {', '.join(ldap_details.get('distinguished_names', [])[:2])}."],
                    action="Use this DN context while reviewing authentication, enumeration, or directory reconnaissance activity.",
                    mitre_technique="T1087",
                    mitre_tactic="Discovery",
                    dedupe_key=f"ldap-dn:{context.session_id}",
                    cooldown=1800,
                )
            )
        kerberos_details = context.protocol_details if context.category == "KERBEROS" else {}
        if context.category == "KERBEROS":
            findings.append(
                DetectionFinding(
                    title="Kerberos service observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=[
                        "Kerberos traffic was observed, which can be useful context during identity investigations.",
                        kerberos_details.get("message_type", "Kerberos message type not parsed."),
                    ],
                    action="Correlate with authentication telemetry if the host later triggers credential-focused alerts.",
                    mitre_technique="T1558",
                    mitre_tactic="Credential Access",
                    dedupe_key=f"kerberos:{context.session_id}",
                    cooldown=1800,
                )
            )
        if context.category == "KERBEROS" and kerberos_details.get("service_principals"):
            findings.append(
                DetectionFinding(
                    title="Kerberos service principal observed",
                    severity="LOW",
                    classification="Protocol dissection",
                    score_delta=1,
                    reasons=[f"Kerberos referenced {', '.join(kerberos_details.get('service_principals', [])[:3])}."],
                    action="Use the SPN context to understand which services the client attempted to access.",
                    mitre_technique="T1558",
                    mitre_tactic="Credential Access",
                    dedupe_key=f"kerberos-spn:{context.session_id}",
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
            "packet_count": state.snapshot.packet_count,
            "outbound_bytes": state.snapshot.outbound_bytes,
            "last_finding": state.snapshot.last_finding,
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


