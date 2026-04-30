from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass
class IOCMatch:
    value: str
    indicator_type: str
    source: str
    confidence: int = 70
    description: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class PacketContext:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    category: str
    detail: str
    packet_len: int
    direction: str
    hostname: str = ""
    base_domain: str = ""
    geo: str = "Unknown"
    trusted: bool = False
    private_pair: bool = False
    dns_query: str = ""
    http_method: str = ""
    http_url: str = ""
    http_host: str = ""
    http_user_agent: str = ""
    http_body_size: int = 0
    http_query_string: str = ""
    tls_version: str = ""
    tls_sni: str = ""
    tls_cert_subject: str = ""
    tls_cert_issuer: str = ""
    tls_self_signed: bool = False
    payload_preview: str = ""
    os_guess: str = ""
    ttl: int = 0
    tcp_window: int = 0
    tcp_flags: int = 0
    session_id: str = ""
    protocol_tags: List[str] = field(default_factory=list)
    ioc_matches: List[IOCMatch] = field(default_factory=list)
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        payload["ioc_matches"] = [match.to_dict() for match in self.ioc_matches]
        return payload


@dataclass
class DetectionFinding:
    title: str
    severity: str
    classification: str
    score_delta: int
    reasons: List[str]
    action: str
    mitre_technique: str
    mitre_tactic: str
    dedupe_key: str
    iocs: List[str] = field(default_factory=list)
    auto_block: bool = False
    cooldown: int = 120
    aggregate_value: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class AlertRecord:
    timestamp: float
    host: str
    destination: str
    severity: str
    title: str
    classification: str
    score: int
    reasons: List[str]
    action: str
    mitre_technique: str
    mitre_tactic: str
    geo: str
    iocs: List[str] = field(default_factory=list)
    dedupe_key: str = ""
    occurrences: int = 1
    recommended_block: str = ""
    session_id: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class SessionRecord:
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    total_bytes: int = 0
    protocol_hints: List[str] = field(default_factory=list)
    snippets: List[str] = field(default_factory=list)
    extracted_artifact: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class HostSnapshot:
    ip: str
    score: int = 0
    severity: str = "LOW"
    packet_count: int = 0
    dns_count: int = 0
    http_count: int = 0
    tls_count: int = 0
    outbound_bytes: int = 0
    top_destination: str = "-"
    last_finding: str = "-"
    os_guess: str = "Unknown"
    baseline_ready: bool = False
    reputation_score: int = 0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
