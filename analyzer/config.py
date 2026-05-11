from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILES_DIR = REPO_ROOT / "profiles"


@dataclass
class PlatformConfig:
    settings_path: str = "app_settings.json"
    interfaces: List[str] = field(default_factory=list)
    pcap_path: Optional[str] = None
    playback_speed: float = 0.0
    export_iocs: Optional[str] = None
    auto_open_browser: bool = True
    dashboard_historical_only: bool = False
    bpf_filter: str = ""
    quick_filter: str = "all"
    geoip_db: str = ""
    database_path: str = "analyzer.db"
    storage_backend: str = "auto"
    packet_parser: str = "scapy"
    report_dir: str = "reports"
    session_dir: str = "reports/sessions"
    artifact_dir: str = "reports/artifacts"
    log_file: str = "reports/analyzer.log"
    ioc_sources: List[str] = field(default_factory=list)
    high_risk_countries: List[str] = field(default_factory=lambda: ["RU", "CN", "KP", "IR"])
    worker_count: int = 2
    alert_cooldown: int = 120
    baseline_min_events: int = 50
    hunt_default_hours: int = 24
    long_term_trend_days: int = 30
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
    stream_preview_chars: int = 2000
    stream_file_chunk_bytes: int = 1_048_576
    artifact_max_bytes: int = 10_000_000
    dashboard_refresh_seconds: int = 5
    asset_inventory_limit: int = 200
    baseline_profile_limit: int = 200
    max_saved_hunts: int = 50
    reassembly_max_fragments: int = 1024
    ml_enabled: bool = True
    sequence_model_enabled: bool = True
    ml_min_global_samples: int = 400
    ml_min_host_samples: int = 120
    sequence_min_transitions: int = 24
    sequence_probability_floor: float = 0.03
    lstm_enabled: bool = False
    lstm_min_samples: int = 600
    lstm_sequence_length: int = 8
    lstm_anomaly_threshold: float = 0.04
    benchmark_default_packets: int = 10000
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
    save_reports_on_exit: bool = False
    report_format: str = "pdf"
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

    def load_user_settings(self) -> "PlatformConfig":
        settings_file = Path(self.settings_path)
        if not settings_file.exists():
            return self
        try:
            payload = json.loads(settings_file.read_text(encoding="utf-8"))
        except Exception:
            return self
        return self.merge(payload)

    def persisted_settings(self) -> Dict[str, Any]:
        payload = asdict(self)
        allowed_keys = {
            "interfaces",
            "bpf_filter",
            "quick_filter",
            "geoip_db",
            "dashboard_refresh_seconds",
            "worker_count",
            "high_risk_countries",
            "ioc_sources",
            "database_path",
            "storage_backend",
            "packet_parser",
            "report_dir",
            "artifact_dir",
            "session_dir",
            "log_file",
            "api_host",
            "api_port",
            "ml_enabled",
            "sequence_model_enabled",
            "ml_min_global_samples",
            "ml_min_host_samples",
            "sequence_min_transitions",
            "sequence_probability_floor",
            "lstm_enabled",
            "lstm_min_samples",
            "lstm_sequence_length",
            "lstm_anomaly_threshold",
            "benchmark_default_packets",
            "dns_tunnel_query_threshold",
            "dns_frequency_window",
            "dns_entropy_threshold",
            "portscan_window",
            "horizontal_port_threshold",
            "vertical_host_threshold",
            "syn_scan_threshold",
            "exfil_window",
            "exfil_bytes_high",
            "exfil_bytes_medium",
            "beacon_min_samples",
            "beacon_max_jitter",
        }
        return {key: payload[key] for key in allowed_keys if key in payload}

    def save_user_settings(self) -> Path:
        settings_file = Path(self.settings_path)
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        settings_file.write_text(json.dumps(self.persisted_settings(), indent=2), encoding="utf-8")
        return settings_file

    def ensure_directories(self) -> None:
        for path in [self.report_dir, self.session_dir, self.artifact_dir]:
            Path(path).mkdir(parents=True, exist_ok=True)
