from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse
from urllib.request import urlopen

from .models import IOCMatch


def normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


@dataclass
class FeedEntry:
    indicator_type: str
    value: str
    source: str
    confidence: int = 70
    description: str = ""


class ThreatIntelManager:
    def __init__(self, sources: Optional[List[str]] = None):
        self.sources = sources or []
        self.ip_feeds: Dict[str, FeedEntry] = {}
        self.domain_feeds: Dict[str, FeedEntry] = {}

    def load_all(self) -> None:
        for source in self.sources:
            try:
                for entry in self._load_source(source):
                    if entry.indicator_type == "ip":
                        self.ip_feeds[entry.value] = entry
                    elif entry.indicator_type == "domain":
                        self.domain_feeds[entry.value] = entry
            except Exception:
                continue

    def _load_source(self, source: str) -> Iterable[FeedEntry]:
        parsed = urlparse(source)
        if parsed.scheme in {"http", "https"}:
            with urlopen(source, timeout=10) as response:
                content = response.read().decode("utf-8", errors="ignore")
            return self._parse_feed_text(content, source)

        content = Path(source).read_text(encoding="utf-8")
        return self._parse_feed_text(content, source)

    def _parse_feed_text(self, content: str, source: str) -> Iterable[FeedEntry]:
        content = content.strip()
        if not content:
            return []

        if content.startswith("["):
            items = json.loads(content)
            return [self._entry_from_json(item, source) for item in items]

        entries: List[FeedEntry] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "," in line:
                parts = [part.strip() for part in line.split(",")]
                if len(parts) >= 4:
                    entries.append(
                        FeedEntry(
                            indicator_type=parts[0],
                            value=self._normalize_value(parts[0], parts[1]),
                            source=parts[2] or source,
                            confidence=int(parts[3] or 70),
                            description=parts[4] if len(parts) > 4 else "",
                        )
                    )
                    continue
            indicator_type = self._guess_type(line)
            entries.append(
                FeedEntry(
                    indicator_type=indicator_type,
                    value=self._normalize_value(indicator_type, line),
                    source=source,
                )
            )
        return entries

    def _entry_from_json(self, item: dict, source: str) -> FeedEntry:
        indicator_type = item.get("type") or self._guess_type(item.get("value", ""))
        value = self._normalize_value(indicator_type, item.get("value", ""))
        return FeedEntry(
            indicator_type=indicator_type,
            value=value,
            source=item.get("source", source),
            confidence=int(item.get("confidence", 70)),
            description=item.get("description", ""),
        )

    def _guess_type(self, value: str) -> str:
        try:
            ipaddress.ip_address(value.strip())
            return "ip"
        except ValueError:
            return "domain"

    def _normalize_value(self, indicator_type: str, value: str) -> str:
        if indicator_type == "domain":
            return normalize_domain(value)
        return value.strip()

    def match(self, ip_values: Iterable[str], domains: Iterable[str]) -> List[IOCMatch]:
        matches: List[IOCMatch] = []
        for ip_value in ip_values:
            entry = self.ip_feeds.get(ip_value)
            if entry:
                matches.append(
                    IOCMatch(
                        value=entry.value,
                        indicator_type=entry.indicator_type,
                        source=entry.source,
                        confidence=entry.confidence,
                        description=entry.description,
                    )
                )

        for domain in domains:
            normalized = normalize_domain(domain)
            if not normalized:
                continue
            direct = self.domain_feeds.get(normalized)
            if direct:
                matches.append(
                    IOCMatch(
                        value=direct.value,
                        indicator_type=direct.indicator_type,
                        source=direct.source,
                        confidence=direct.confidence,
                        description=direct.description,
                    )
                )
                continue

            parts = normalized.split(".")
            for index in range(1, len(parts)):
                suffix = ".".join(parts[index:])
                entry = self.domain_feeds.get(suffix)
                if entry:
                    matches.append(
                        IOCMatch(
                            value=entry.value,
                            indicator_type=entry.indicator_type,
                            source=entry.source,
                            confidence=entry.confidence,
                            description=entry.description,
                        )
                    )
                    break
        return matches
