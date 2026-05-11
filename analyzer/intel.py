from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen

from .models import IOCMatch


def normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def re_split_talos_line(value: str) -> List[str]:
    return [part.strip() for part in re.split(r"[,|\t ]+", value) if part.strip()]


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
        self.feed_status: List[Dict[str, object]] = []

    def load_all(self) -> None:
        self.ip_feeds = {}
        self.domain_feeds = {}
        self.feed_status = []
        for source in self.sources:
            loaded = 0
            error = ""
            try:
                for entry in self._load_source(source):
                    if not entry.value:
                        continue
                    if entry.indicator_type == "ip":
                        self.ip_feeds[entry.value] = entry
                        loaded += 1
                    elif entry.indicator_type == "domain":
                        self.domain_feeds[entry.value] = entry
                        loaded += 1
            except Exception as exc:
                error = str(exc)
            self.feed_status.append({"source": source, "loaded": loaded, "error": error})

    def _load_source(self, source: str) -> Iterable[FeedEntry]:
        parsed = urlparse(source)
        if parsed.scheme in {"abuseipdb", "urlhaus", "otx", "tor", "talos"}:
            return self._load_built_in_feed(parsed, source)
        if parsed.scheme in {"http", "https"}:
            content = self._fetch_text(source)
            return self._parse_feed_text(content, source)
        content = Path(source).read_text(encoding="utf-8")
        return self._parse_feed_text(content, source)

    def _load_built_in_feed(self, parsed, source: str) -> Iterable[FeedEntry]:
        scheme = parsed.scheme.lower()
        params = {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}
        if scheme == "abuseipdb":
            return self._load_abuseipdb(source, params)
        if scheme == "urlhaus":
            return self._load_urlhaus(source, params)
        if scheme == "otx":
            return self._load_otx(source, params)
        if scheme == "tor":
            return self._load_tor(source, params)
        if scheme == "talos":
            return self._load_talos(source, params)
        return []

    def _load_abuseipdb(self, source: str, params: Dict[str, str]) -> Iterable[FeedEntry]:
        api_key = params.get("api_key") or os.getenv(params.get("api_key_env", "ABUSEIPDB_API_KEY"), "")
        if not api_key:
            return []
        query = {
            "confidenceMinimum": params.get("confidenceMinimum", "90"),
            "limit": params.get("limit", "10000"),
        }
        endpoint = params.get("url") or "https://api.abuseipdb.com/api/v2/blacklist"
        url = f"{endpoint}?{urlencode(query)}"
        content = self._fetch_text(
            url,
            headers={
                "Accept": "text/plain",
                "Key": api_key,
            },
        )
        return self._parse_feed_text(content, source)

    def _load_urlhaus(self, source: str, params: Dict[str, str]) -> Iterable[FeedEntry]:
        auth_key = params.get("auth_key") or os.getenv(params.get("auth_key_env", "URLHAUS_AUTH_KEY"), "")
        if auth_key:
            dataset = params.get("dataset", "recent.csv")
            url = params.get("url") or f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/{dataset}"
        else:
            url = params.get("url") or "https://urlhaus.abuse.ch/downloads/text_online/"
        content = self._fetch_text(url)
        return self._parse_feed_text(content, source)

    def _load_otx(self, source: str, params: Dict[str, str]) -> Iterable[FeedEntry]:
        api_key = params.get("api_key") or os.getenv(params.get("api_key_env", "OTX_API_KEY"), "")
        if not api_key:
            return []
        query = {"types": params.get("types", "IPv4,domain,hostname,URL")}
        endpoint = params.get("url") or "https://otx.alienvault.com/api/v1/indicators/export"
        url = f"{endpoint}?{urlencode(query)}"
        content = self._fetch_text(
            url,
            headers={
                "Accept": "text/plain",
                "X-OTX-API-KEY": api_key,
            },
        )
        return self._parse_feed_text(content, source)

    def _load_tor(self, source: str, params: Dict[str, str]) -> Iterable[FeedEntry]:
        url = params.get("url") or "https://check.torproject.org/exit-addresses"
        content = self._fetch_text(url)
        entries: List[FeedEntry] = []
        for raw_line in content.splitlines():
            parts = raw_line.strip().split()
            if len(parts) >= 2 and parts[0] == "ExitAddress":
                value = parts[1].strip()
                if self._guess_type(value) == "ip":
                    entries.append(
                        FeedEntry(
                            indicator_type="ip",
                            value=value,
                            source=source,
                            confidence=55,
                            description="Tor exit node",
                        )
                    )
        return entries

    def _load_talos(self, source: str, params: Dict[str, str]) -> Iterable[FeedEntry]:
        url = params.get("url") or os.getenv(params.get("url_env", "TALOS_FEED_URL"), "")
        if not url:
            return []
        content = self._fetch_text(url)
        return self._parse_talos_text(content, source)

    def _fetch_text(self, url: str, headers: Optional[Dict[str, str]] = None) -> str:
        request = Request(url, headers=headers or {})
        with urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8", errors="ignore")

    def _parse_feed_text(self, content: str, source: str) -> Iterable[FeedEntry]:
        content = content.strip()
        if not content:
            return []

        if content.startswith("{"):
            parsed = json.loads(content)
            if isinstance(parsed, dict) and isinstance(parsed.get("data"), list):
                return [self._entry_from_json(item, source) for item in parsed["data"]]

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
                if len(parts) >= 4 and parts[0] in {"ip", "domain"}:
                    value = self._normalize_value(parts[0], parts[1])
                    if value:
                        entries.append(
                            FeedEntry(
                                indicator_type=parts[0],
                                value=value,
                                source=parts[2] or source,
                                confidence=int(parts[3] or 70),
                                description=parts[4] if len(parts) > 4 else "",
                            )
                        )
                        continue
                extracted = self._extract_indicator_from_text(parts)
                if extracted:
                    indicator_type, value = extracted
                    entries.append(
                        FeedEntry(
                            indicator_type=indicator_type,
                            value=value,
                            source=source,
                            confidence=70,
                        )
                    )
                    continue
            extracted = self._extract_indicator_from_text([line])
            if not extracted:
                continue
            indicator_type, value = extracted
            entries.append(
                FeedEntry(
                    indicator_type=indicator_type,
                    value=value,
                    source=source,
                )
            )
        return entries

    def _parse_talos_text(self, content: str, source: str) -> Iterable[FeedEntry]:
        parsed = list(self._parse_feed_text(content, source))
        if parsed:
            for entry in parsed:
                entry.source = "Cisco Talos" if entry.source == source else entry.source
                if not entry.description:
                    entry.description = "Cisco Talos reputation indicator"
            return parsed

        entries: List[FeedEntry] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fragments = re_split_talos_line(line)
            extracted = self._extract_indicator_from_text(fragments)
            if not extracted:
                continue
            indicator_type, value = extracted
            confidence = 80 if any("malicious" in item.lower() or "poor" in item.lower() for item in fragments) else 65
            entries.append(
                FeedEntry(
                    indicator_type=indicator_type,
                    value=value,
                    source="Cisco Talos",
                    confidence=confidence,
                    description="Cisco Talos reputation indicator",
                )
            )
        return entries

    def _extract_indicator_from_text(self, fragments: List[str]) -> Optional[tuple[str, str]]:
        for fragment in fragments:
            value = fragment.strip()
            if not value:
                continue
            if "://" in value:
                parsed = urlparse(value)
                host = normalize_domain(parsed.hostname or "")
                if host:
                    indicator_type = self._guess_type(host)
                    return indicator_type, self._normalize_value(indicator_type, host)
            if "/" in value and not value.startswith("/"):
                try:
                    parsed = urlparse(f"http://{value}")
                    host = normalize_domain(parsed.hostname or "")
                    if host and "." in host:
                        indicator_type = self._guess_type(host)
                        return indicator_type, self._normalize_value(indicator_type, host)
                except Exception:
                    pass
            indicator_type = self._guess_type(value)
            normalized = self._normalize_value(indicator_type, value)
            if normalized:
                return indicator_type, normalized
        return None

    def _entry_from_json(self, item: dict, source: str) -> FeedEntry:
        value = (
            item.get("value")
            or item.get("ipAddress")
            or item.get("indicator")
            or item.get("domain")
            or item.get("hostname")
            or ""
        )
        indicator_type = item.get("type") or self._guess_type(str(value))
        normalized = self._normalize_value(indicator_type, str(value))
        return FeedEntry(
            indicator_type=indicator_type if indicator_type in {"ip", "domain"} else self._guess_type(normalized),
            value=normalized,
            source=item.get("source", source),
            confidence=int(item.get("confidence", item.get("abuseConfidenceScore", 70)) or 70),
            description=item.get("description", ""),
        )

    def _guess_type(self, value: str) -> str:
        try:
            ipaddress.ip_address(value.strip())
            return "ip"
        except ValueError:
            return "domain"

    def _normalize_value(self, indicator_type: str, value: str) -> str:
        clean = value.strip()
        if not clean:
            return ""
        if indicator_type == "domain":
            domain = normalize_domain(clean)
            if not domain or " " in domain or "." not in domain:
                return ""
            return domain
        try:
            return str(ipaddress.ip_address(clean))
        except ValueError:
            return ""

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
