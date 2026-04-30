from __future__ import annotations

import json
from pathlib import Path
import smtplib
from typing import Dict, Optional
from urllib.request import Request, urlopen

from .config import PlatformConfig
from .models import AlertRecord


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def format_console_alert(alert: AlertRecord) -> str:
    reasons = "\n".join(f" - {reason}" for reason in alert.reasons)
    return (
        f"[{alert.severity}] {alert.title}\n"
        f"Host: {alert.host}\n"
        f"Destination: {alert.destination}\n"
        f"MITRE: {alert.mitre_tactic} / {alert.mitre_technique}\n"
        f"Score: {alert.score}\n"
        f"Why:\n{reasons}\n"
        f"Action: {alert.action}\n"
    )


def to_cef(alert: AlertRecord) -> str:
    reason_blob = " | ".join(alert.reasons)
    return (
        "CEF:0|AdvancedNetworkAnalyzer|ThreatPlatform|1.0|"
        f"{alert.classification}|{alert.title}|{SEVERITY_RANK.get(alert.severity, 1)}|"
        f"src={alert.host} dst={alert.destination} msg={reason_blob} "
        f"cs1Label=MITRE_Technique cs1={alert.mitre_technique} "
        f"cs2Label=MITRE_Tactic cs2={alert.mitre_tactic}"
    )


class AlertRouter:
    def __init__(self, config: PlatformConfig):
        self.config = config
        self.log_path = Path(config.log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.dedup_cache: Dict[str, Dict[str, object]] = {}

    def should_emit(self, alert: AlertRecord, cooldown: int) -> bool:
        cache = self.dedup_cache.get(alert.dedupe_key)
        if not cache:
            self.dedup_cache[alert.dedupe_key] = {"timestamp": alert.timestamp, "count": 1}
            return True

        if alert.timestamp - float(cache["timestamp"]) > cooldown:
            self.dedup_cache[alert.dedupe_key] = {"timestamp": alert.timestamp, "count": 1}
            return True

        cache["count"] = int(cache["count"]) + 1
        return False

    def get_occurrences(self, dedupe_key: str) -> int:
        cache = self.dedup_cache.get(dedupe_key)
        return int(cache["count"]) if cache else 1

    def emit(self, alert: AlertRecord) -> None:
        print(format_console_alert(alert))
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict()) + "\n")

        if self.config.webhook_enabled and self.config.webhook_url:
            self._send_webhook(alert)
        if self.config.email_enabled and self.config.smtp_host and self.config.smtp_to:
            self._send_email(alert)

    def _send_webhook(self, alert: AlertRecord) -> None:
        payload = {
            "text": f"{alert.severity}: {alert.title}",
            "alert": alert.to_dict(),
            "cef": to_cef(alert),
        }
        request = Request(
            self.config.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10):
                return
        except Exception:
            return

    def _send_email(self, alert: AlertRecord) -> None:
        message = (
            f"Subject: [{alert.severity}] {alert.title}\n\n"
            f"{format_console_alert(alert)}\nCEF:\n{to_cef(alert)}\n"
        )
        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=10) as server:
                server.starttls()
                if self.config.smtp_username:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                server.sendmail(self.config.smtp_from, self.config.smtp_to, message)
        except Exception:
            return
