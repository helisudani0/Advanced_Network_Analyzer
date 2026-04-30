from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILES_DIR = REPO_ROOT / "profiles"


@dataclass
class PlatformConfig:
    interfaces: List[str] = field(default_factory=list)
    pcap_path: Optional[str] = None
    playback_speed: float = 0.0
    bpf_filter: str = ""
    quick_filter: str = "all"
    geoip_db: str = ""
    database_path: str = "analyzer.db"
    report_dir: str = "reports"
    session_dir: str = "reports/sessions"
    artifact_dir: str = "reports/artifacts"
    log_file: str = "reports/analyzer.log"
    ioc_sources: List[str] = field(default_factory=list)
    high_risk_countries: List[str] = field(default_factory=lambda: ["RU", "CN", "KP", "IR"])
    worker_count: int = 2
    alert_cooldown: int = 120
    baseline_min_events: int = 50
    dns_tunnel_query_threshold: int = 30
    dns_frequency_window: int = 60
    dns_entropy_threshold: float = 4.1
    portscan_window: int = 30
    horizontal_port_threshold: int = 25
    vertical_host_threshold: int = 20
    syn_scan_threshold: int = 70
    exfil_window: int = 120
    exfil_bytes_high: int = 5_000_000
    exfil_bytes_medium: int = 1_500_000
    beacon_min_samples: int = 6
    beacon_max_jitter: float = 0.18
    webhook_url: str = ""
    webhook_enabled: bool = False
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: List[str] = field(default_factory=list)
    api_enabled: bool = False
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    save_reports_on_exit: bool = True
    report_format: str = "html"
    max_queue_size: int = 5000

    @classmethod
    def from_profile(cls, profile_name_or_path: Optional[str]) -> "PlatformConfig":
        config = cls()
        if not profile_name_or_path:
            return config

        candidate = Path(profile_name_or_path)
        if not candidate.exists():
            candidate = PROFILES_DIR / f"{profile_name_or_path}.json"
        if not candidate.exists():
            raise FileNotFoundError(f"Profile not found: {profile_name_or_path}")

        payload = json.loads(candidate.read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "PlatformConfig":
        config = cls()
        for key, value in payload.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config

    def merge(self, overrides: Dict[str, Any]) -> "PlatformConfig":
        payload = asdict(self)
        for key, value in overrides.items():
            if value is not None and key in payload:
                payload[key] = value
        return PlatformConfig.from_dict(payload)

    def ensure_directories(self) -> None:
        for path in [self.report_dir, self.session_dir, self.artifact_dir]:
            Path(path).mkdir(parents=True, exist_ok=True)
