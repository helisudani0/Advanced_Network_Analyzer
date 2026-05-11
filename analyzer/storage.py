from __future__ import annotations

from collections import Counter, defaultdict
import ipaddress
import json
import sqlite3
import threading
import time
from typing import Dict, Iterable, List, Optional

from .models import AlertRecord, PacketContext, SessionRecord

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None

try:
    import psycopg2
    import psycopg2.extras
except Exception:
    psycopg2 = None


def _is_postgres_target(target: str) -> bool:
    return target.startswith("postgresql://") or target.startswith("postgres://")


def _is_sqlalchemy_target(target: str) -> bool:
    return target.startswith("sqlalchemy+")


def _is_private_ip(ip_value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


class DatabaseStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        self.backend = "postgres" if _is_postgres_target(database_path) else "sqlite"
        self.driver = "sqlite3"
        self.lock = threading.Lock()
        self.connection = self._connect(database_path)
        self.bind = "%s" if self.backend == "postgres" else "?"
        self._initialize()

    def _connect(self, database_path: str):
        if self.backend == "postgres":
            if psycopg is not None:
                self.driver = "psycopg"
                return psycopg.connect(database_path, row_factory=dict_row)
            if psycopg2 is not None:
                self.driver = "psycopg2"
                connection = psycopg2.connect(
                    database_path,
                    cursor_factory=psycopg2.extras.RealDictCursor,
                )
                connection.autocommit = False
                return connection
            raise RuntimeError(
                "PostgreSQL support requires a PostgreSQL driver. Install requirements.txt or "
                "install 'psycopg[binary]' or 'psycopg2-binary' before using a PostgreSQL URL."
            )

        connection = sqlite3.connect(database_path, check_same_thread=False, timeout=5.0)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        try:
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA temp_store=MEMORY")
        finally:
            cursor.close()
        return connection

    def _execute(self, query: str, values: Iterable[object] = ()) -> None:
        prepared = tuple(values)
        for attempt in range(8):
            try:
                with self.lock:
                    cursor = self.connection.cursor()
                    try:
                        cursor.execute(query, prepared)
                        self.connection.commit()
                        return
                    finally:
                        cursor.close()
            except sqlite3.OperationalError as exc:
                locked = self.backend == "sqlite" and "database is locked" in str(exc).lower()
                if not locked or attempt >= 7:
                    raise
                try:
                    self.connection.rollback()
                except Exception:
                    pass
                time.sleep(min(1.5, 0.1 * (attempt + 1)))

    def _fetchall(self, query: str, values: Iterable[object] = ()) -> List[Dict[str, object]]:
        prepared = tuple(values)
        for attempt in range(8):
            try:
                with self.lock:
                    cursor = self.connection.cursor()
                    try:
                        cursor.execute(query, prepared)
                        rows = cursor.fetchall()
                    finally:
                        cursor.close()
                return [dict(row) for row in rows]
            except sqlite3.OperationalError as exc:
                locked = self.backend == "sqlite" and "database is locked" in str(exc).lower()
                if not locked or attempt >= 7:
                    raise
                time.sleep(min(1.5, 0.1 * (attempt + 1)))
        return []

    def _fetchone(self, query: str, values: Iterable[object] = ()) -> Optional[Dict[str, object]]:
        rows = self._fetchall(query, values)
        return rows[0] if rows else None

    def _placeholders(self, count: int) -> str:
        return ", ".join([self.bind] * count)

    def _initialize(self) -> None:
        if self.backend == "postgres":
            statements = [
                """
                CREATE TABLE IF NOT EXISTS events (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp DOUBLE PRECISION,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    transport TEXT,
                    category TEXT,
                    hostname TEXT,
                    base_domain TEXT,
                    geo TEXT,
                    direction TEXT,
                    packet_len INTEGER,
                    session_id TEXT,
                    payload_preview TEXT,
                    user_agent TEXT,
                    http_url TEXT,
                    tls_version TEXT,
                    tls_sni TEXT,
                    os_guess TEXT,
                    risk_score INTEGER,
                    risk_factors_json TEXT,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id BIGSERIAL PRIMARY KEY,
                    timestamp DOUBLE PRECISION,
                    host TEXT,
                    destination TEXT,
                    severity TEXT,
                    title TEXT,
                    classification TEXT,
                    score INTEGER,
                    reasons_json TEXT,
                    action TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    geo TEXT,
                    iocs_json TEXT,
                    dedupe_key TEXT,
                    occurrences INTEGER,
                    recommended_block TEXT,
                    session_id TEXT,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    transport TEXT,
                    first_seen DOUBLE PRECISION,
                    last_seen DOUBLE PRECISION,
                    packet_count INTEGER,
                    total_bytes BIGINT,
                    protocol_hints_json TEXT,
                    snippets_json TEXT,
                    extracted_artifact TEXT,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS baselines (
                    host TEXT PRIMARY KEY,
                    updated_at DOUBLE PRECISION,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saved_hunts (
                    id BIGSERIAL PRIMARY KEY,
                    name TEXT UNIQUE,
                    dataset TEXT,
                    notes TEXT,
                    created_at DOUBLE PRECISION,
                    updated_at DOUBLE PRECISION,
                    query_json TEXT
                )
                """,
            ]
        else:
            statements = [
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    transport TEXT,
                    category TEXT,
                    hostname TEXT,
                    base_domain TEXT,
                    geo TEXT,
                    direction TEXT,
                    packet_len INTEGER,
                    session_id TEXT,
                    payload_preview TEXT,
                    user_agent TEXT,
                    http_url TEXT,
                    tls_version TEXT,
                    tls_sni TEXT,
                    os_guess TEXT,
                    risk_score INTEGER,
                    risk_factors_json TEXT,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    host TEXT,
                    destination TEXT,
                    severity TEXT,
                    title TEXT,
                    classification TEXT,
                    score INTEGER,
                    reasons_json TEXT,
                    action TEXT,
                    mitre_technique TEXT,
                    mitre_tactic TEXT,
                    geo TEXT,
                    iocs_json TEXT,
                    dedupe_key TEXT,
                    occurrences INTEGER,
                    recommended_block TEXT,
                    session_id TEXT,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    transport TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    packet_count INTEGER,
                    total_bytes INTEGER,
                    protocol_hints_json TEXT,
                    snippets_json TEXT,
                    extracted_artifact TEXT,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS baselines (
                    host TEXT PRIMARY KEY,
                    updated_at REAL,
                    json_blob TEXT
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saved_hunts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    dataset TEXT,
                    notes TEXT,
                    created_at REAL,
                    updated_at REAL,
                    query_json TEXT
                )
                """,
            ]

        with self.lock:
            cursor = self.connection.cursor()
            for statement in statements:
                cursor.execute(statement)
            self.connection.commit()

    def insert_event(self, context: PacketContext) -> None:
        payload = context.to_dict()
        columns = (
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "transport", "category",
            "hostname", "base_domain", "geo", "direction", "packet_len", "session_id",
            "payload_preview", "user_agent", "http_url", "tls_version", "tls_sni", "os_guess",
            "risk_score", "risk_factors_json", "json_blob",
        )
        values = (
            context.timestamp,
            context.src_ip,
            context.dst_ip,
            context.src_port,
            context.dst_port,
            context.transport,
            context.category,
            context.hostname,
            context.base_domain,
            context.geo,
            context.direction,
            context.packet_len,
            context.session_id,
            context.payload_preview,
            context.http_user_agent,
            context.http_url,
            context.tls_version,
            context.tls_sni,
            context.os_guess,
            context.risk_score,
            json.dumps(context.risk_factors),
            json.dumps(payload),
        )
        query = (
            f"INSERT INTO events ({', '.join(columns)}) "
            f"VALUES ({self._placeholders(len(values))})"
        )
        self._execute(query, values)

    def insert_alert(self, alert: AlertRecord) -> None:
        payload = alert.to_dict()
        columns = (
            "timestamp", "host", "destination", "severity", "title", "classification", "score",
            "reasons_json", "action", "mitre_technique", "mitre_tactic", "geo", "iocs_json",
            "dedupe_key", "occurrences", "recommended_block", "session_id", "json_blob",
        )
        values = (
            alert.timestamp,
            alert.host,
            alert.destination,
            alert.severity,
            alert.title,
            alert.classification,
            alert.score,
            json.dumps(alert.reasons),
            alert.action,
            alert.mitre_technique,
            alert.mitre_tactic,
            alert.geo,
            json.dumps(alert.iocs),
            alert.dedupe_key,
            alert.occurrences,
            alert.recommended_block,
            alert.session_id,
            json.dumps(payload),
        )
        query = (
            f"INSERT INTO alerts ({', '.join(columns)}) "
            f"VALUES ({self._placeholders(len(values))})"
        )
        self._execute(query, values)

    def upsert_session(self, session: SessionRecord) -> None:
        payload = session.to_dict()
        values = (
            session.session_id,
            session.src_ip,
            session.dst_ip,
            session.src_port,
            session.dst_port,
            session.transport,
            session.first_seen,
            session.last_seen,
            session.packet_count,
            session.total_bytes,
            json.dumps(session.protocol_hints),
            json.dumps(session.snippets),
            session.extracted_artifact,
            json.dumps(payload),
        )
        query = (
            "INSERT INTO sessions ("
            "session_id, src_ip, dst_ip, src_port, dst_port, transport, first_seen, "
            "last_seen, packet_count, total_bytes, protocol_hints_json, snippets_json, "
            "extracted_artifact, json_blob"
            f") VALUES ({self._placeholders(len(values))}) "
            "ON CONFLICT(session_id) DO UPDATE SET "
            "last_seen=EXCLUDED.last_seen, "
            "packet_count=EXCLUDED.packet_count, "
            "total_bytes=EXCLUDED.total_bytes, "
            "protocol_hints_json=EXCLUDED.protocol_hints_json, "
            "snippets_json=EXCLUDED.snippets_json, "
            "extracted_artifact=EXCLUDED.extracted_artifact, "
            "json_blob=EXCLUDED.json_blob"
        )
        self._execute(query, values)

    def upsert_baseline(self, host: str, updated_at: float, payload: Dict[str, object]) -> None:
        values = (host, updated_at, json.dumps(payload))
        query = (
            "INSERT INTO baselines (host, updated_at, json_blob) "
            f"VALUES ({self._placeholders(len(values))}) "
            "ON CONFLICT(host) DO UPDATE SET "
            "updated_at=EXCLUDED.updated_at, "
            "json_blob=EXCLUDED.json_blob"
        )
        self._execute(query, values)

    def save_hunt_query(self, name: str, dataset: str, query: Dict[str, object], notes: str = "") -> None:
        now = time.time()
        values = (name, dataset, notes, now, now, json.dumps(query))
        query_sql = (
            "INSERT INTO saved_hunts (name, dataset, notes, created_at, updated_at, query_json) "
            f"VALUES ({self._placeholders(len(values))}) "
            "ON CONFLICT(name) DO UPDATE SET "
            "dataset=EXCLUDED.dataset, "
            "notes=EXCLUDED.notes, "
            "updated_at=EXCLUDED.updated_at, "
            "query_json=EXCLUDED.query_json"
        )
        self._execute(query_sql, values)

    def delete_saved_hunt_query(self, name: str) -> None:
        self._execute(f"DELETE FROM saved_hunts WHERE name = {self.bind}", (name,))

    def _fetch_json_rows(self, table: str, order_by: str, limit: int) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"SELECT json_blob FROM {table} ORDER BY {order_by} DESC LIMIT {self.bind}",
            (limit,),
        )
        return [json.loads(row["json_blob"]) for row in rows]

    def fetch_alerts(self, limit: int = 100) -> List[Dict[str, object]]:
        return self._fetch_json_rows("alerts", "timestamp", limit)

    def fetch_sessions(self, limit: int = 100) -> List[Dict[str, object]]:
        return self._fetch_json_rows("sessions", "last_seen", limit)

    def fetch_events(self, limit: int = 200) -> List[Dict[str, object]]:
        return self._fetch_json_rows("events", "timestamp", limit)

    def fetch_events_for_session(self, session_id: str, limit: int = 200) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"SELECT json_blob FROM events WHERE session_id = {self.bind} ORDER BY timestamp DESC LIMIT {self.bind}",
            (session_id, limit),
        )
        return [json.loads(row["json_blob"]) for row in rows]

    def fetch_alerts_for_session(self, session_id: str, limit: int = 100) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"SELECT json_blob FROM alerts WHERE session_id = {self.bind} ORDER BY timestamp DESC LIMIT {self.bind}",
            (session_id, limit),
        )
        return [json.loads(row["json_blob"]) for row in rows]

    def _session_side(self, session: Dict[str, object], event: Dict[str, object]) -> str:
        src_ip = str(event.get("src_ip", ""))
        dst_ip = str(event.get("dst_ip", ""))
        src_port = int(event.get("src_port") or 0)
        dst_port = int(event.get("dst_port") or 0)
        session_src = str(session.get("src_ip", ""))
        session_dst = str(session.get("dst_ip", ""))
        session_src_port = int(session.get("src_port") or 0)
        session_dst_port = int(session.get("dst_port") or 0)
        if src_ip == session_src and src_port == session_src_port:
            return "client -> server"
        if src_ip == session_dst and src_port == session_dst_port:
            return "server -> client"
        if dst_ip == session_src and dst_port == session_src_port:
            return "server -> client"
        return str(event.get("direction") or "observed")

    def _session_event_summary(self, event: Dict[str, object]) -> str:
        protocol = str(event.get("category") or event.get("transport") or "TRAFFIC")
        endpoint = (
            f"{event.get('src_ip', '')}:{event.get('src_port', '')} -> "
            f"{event.get('dst_ip', '')}:{event.get('dst_port', '')}"
        )
        details = []
        if event.get("http_method") or event.get("http_url"):
            details.append(f"{event.get('http_method', '')} {event.get('http_url', '')}".strip())
        if event.get("dns_query"):
            details.append(f"DNS {event.get('dns_query')}")
        if event.get("tls_version") or event.get("tls_sni"):
            details.append(f"TLS {event.get('tls_version', '')} {event.get('tls_sni', '')}".strip())
        if event.get("detail"):
            details.append(str(event.get("detail")))
        if event.get("payload_preview"):
            preview = str(event.get("payload_preview", "")).replace("\r", " ").replace("\n", " ")
            details.append(f"payload={preview[:180]}")
        detail_text = " | ".join(item for item in details if item)
        return f"{protocol} {endpoint}" + (f" | {detail_text}" if detail_text else "")

    def _build_session_conversation(
        self,
        session: Dict[str, object],
        events: List[Dict[str, object]],
        alerts: List[Dict[str, object]],
    ) -> List[Dict[str, object]]:
        conversation: List[Dict[str, object]] = []
        for event in sorted(events, key=lambda item: float(item.get("timestamp") or 0)):
            conversation.append(
                {
                    "timestamp": float(event.get("timestamp") or 0),
                    "kind": "event",
                    "side": self._session_side(session, event),
                    "protocol": event.get("category") or event.get("transport") or "",
                    "summary": self._session_event_summary(event),
                    "bytes": int(event.get("packet_len") or 0),
                    "risk_score": int(event.get("risk_score") or 0),
                    "payload_preview": event.get("payload_preview", ""),
                    "ioc_matches": event.get("ioc_matches", []),
                }
            )
        for alert in sorted(alerts, key=lambda item: float(item.get("timestamp") or 0)):
            reasons = " ".join(str(item) for item in alert.get("reasons", [])[:2])
            conversation.append(
                {
                    "timestamp": float(alert.get("timestamp") or 0),
                    "kind": "detection",
                    "side": "analysis",
                    "protocol": alert.get("classification") or "",
                    "summary": (
                        f"{alert.get('severity', 'LOW')} {alert.get('title', 'Detection')}"
                        f" | {alert.get('mitre_tactic', '')} {alert.get('mitre_technique', '')}"
                        + (f" | {reasons}" if reasons else "")
                    ),
                    "bytes": 0,
                    "risk_score": int(alert.get("score") or 0),
                    "payload_preview": "",
                    "ioc_matches": alert.get("iocs", []),
                }
            )
        conversation.sort(key=lambda item: float(item.get("timestamp") or 0))
        return conversation[:240]

    def _build_session_transcript(self, conversation: List[Dict[str, object]]) -> str:
        lines = []
        for item in conversation:
            timestamp = float(item.get("timestamp") or 0)
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)) if timestamp else "unknown-time"
            side = str(item.get("side") or "observed")
            kind = str(item.get("kind") or "event")
            summary = str(item.get("summary") or "")
            lines.append(f"[{stamp}] {side} {kind}: {summary}")
        return "\n".join(lines)

    def fetch_top_riskiest(self, limit: int = 10) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"""
            SELECT host, MAX(score) AS max_score, COUNT(*) AS alert_count
            FROM alerts
            GROUP BY host
            ORDER BY max_score DESC, alert_count DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )
        return rows

    def fetch_mitre_heatmap(self) -> List[Dict[str, object]]:
        return self._fetchall(
            """
            SELECT mitre_tactic, mitre_technique, COUNT(*) AS total
            FROM alerts
            GROUP BY mitre_tactic, mitre_technique
            ORDER BY total DESC
            """
        )

    def fetch_alert_counts(self) -> Dict[str, int]:
        rows = self._fetchall("SELECT severity, COUNT(*) AS total FROM alerts GROUP BY severity")
        return {str(row["severity"]): int(row["total"]) for row in rows}

    def fetch_protocol_distribution(self, limit: int = 20) -> List[Dict[str, object]]:
        return self._fetchall(
            f"""
            SELECT category, COUNT(*) AS total
            FROM events
            GROUP BY category
            ORDER BY total DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )

    def fetch_top_talkers(self, limit: int = 10) -> List[Dict[str, object]]:
        return self._fetchall(
            f"""
            SELECT src_ip, COUNT(*) AS packets, COALESCE(SUM(packet_len), 0) AS bytes
            FROM events
            GROUP BY src_ip
            ORDER BY packets DESC, bytes DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )

    def fetch_geo_summary(self, limit: int = 20) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"""
            SELECT geo, COUNT(*) AS total
            FROM events
            WHERE geo IS NOT NULL
              AND geo != ''
              AND geo != 'Private/Local'
              AND geo != 'GeoIP unavailable'
              AND geo != 'Unknown'
            GROUP BY geo
            ORDER BY total DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )
        for row in rows:
            geo = str(row.get("geo") or "")
            parts = [part.strip() for part in geo.split("/", 1)]
            row["country"] = parts[0] if parts else geo
            row["city"] = parts[1] if len(parts) > 1 else ""
        return rows

    def rebuild_geoip(self, lookup_fn, limit: int = 5000) -> int:
        rows = self._fetchall(
            f"""
            SELECT id, dst_ip, geo, json_blob
            FROM events
            WHERE dst_ip IS NOT NULL AND dst_ip != ''
            ORDER BY timestamp DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )
        updated = 0
        for row in rows:
            dst_ip = str(row.get("dst_ip") or "")
            previous = str(row.get("geo") or "")
            next_geo = str(lookup_fn(dst_ip) or "")
            if not next_geo or next_geo == previous or next_geo in {"GeoIP unavailable", "Unknown"}:
                continue
            try:
                payload = json.loads(str(row.get("json_blob") or "{}"))
                payload["geo"] = next_geo
                json_blob = json.dumps(payload)
            except Exception:
                json_blob = row.get("json_blob") or "{}"
            self._execute(
                f"UPDATE events SET geo = {self.bind}, json_blob = {self.bind} WHERE id = {self.bind}",
                (next_geo, json_blob, row["id"]),
            )
            updated += 1
        return updated

    def fetch_alert_timeline(self, limit: int = 100) -> List[Dict[str, object]]:
        return self._fetchall(
            f"""
            SELECT timestamp, severity, title, host, destination, mitre_technique
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )

    def search_alerts(
        self,
        classification: str = "",
        severity: str = "",
        technique: str = "",
        host: str = "",
        destination: str = "",
        text_query: str = "",
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 200,
    ) -> List[Dict[str, object]]:
        clauses = []
        values: List[object] = []
        if classification:
            clauses.append(f"classification = {self.bind}")
            values.append(classification)
        if severity:
            clauses.append(f"severity = {self.bind}")
            values.append(severity)
        if technique:
            clauses.append(f"mitre_technique = {self.bind}")
            values.append(technique)
        if host:
            clauses.append(f"host = {self.bind}")
            values.append(host)
        if destination:
            clauses.append(f"destination LIKE {self.bind}")
            values.append(f"%{destination}%")
        if start_ts is not None:
            clauses.append(f"timestamp >= {self.bind}")
            values.append(start_ts)
        if end_ts is not None:
            clauses.append(f"timestamp <= {self.bind}")
            values.append(end_ts)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT json_blob FROM alerts {where} ORDER BY timestamp DESC LIMIT {self.bind}"
        values.append(limit)
        rows = self._fetchall(query, values)
        alerts = [json.loads(row["json_blob"]) for row in rows]
        if text_query:
            needle = text_query.lower()
            alerts = [row for row in alerts if needle in json.dumps(row).lower()]
        return alerts

    def search_events(
        self,
        host: str = "",
        destination: str = "",
        protocol: str = "",
        domain: str = "",
        text_query: str = "",
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 200,
    ) -> List[Dict[str, object]]:
        clauses = []
        values: List[object] = []
        if host:
            clauses.append(f"(src_ip = {self.bind} OR dst_ip = {self.bind})")
            values.extend([host, host])
        if destination:
            clauses.append(f"(dst_ip = {self.bind} OR hostname LIKE {self.bind})")
            values.extend([destination, f"%{destination}%"])
        if protocol:
            clauses.append(f"category = {self.bind}")
            values.append(protocol)
        if domain:
            clauses.append(f"(base_domain = {self.bind} OR hostname LIKE {self.bind})")
            values.extend([domain, f"%{domain}%"])
        if start_ts is not None:
            clauses.append(f"timestamp >= {self.bind}")
            values.append(start_ts)
        if end_ts is not None:
            clauses.append(f"timestamp <= {self.bind}")
            values.append(end_ts)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT json_blob FROM events {where} ORDER BY timestamp DESC LIMIT {self.bind}"
        values.append(limit)
        rows = self._fetchall(query, values)
        events = [json.loads(row["json_blob"]) for row in rows]
        if text_query:
            needle = text_query.lower()
            events = [row for row in events if needle in json.dumps(row).lower()]
        return events

    def search_sessions(
        self,
        host: str = "",
        destination: str = "",
        protocol: str = "",
        artifact_only: bool = False,
        min_bytes: int = 0,
        text_query: str = "",
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        limit: int = 200,
    ) -> List[Dict[str, object]]:
        clauses = []
        values: List[object] = []
        if host:
            clauses.append(f"(src_ip = {self.bind} OR dst_ip = {self.bind})")
            values.extend([host, host])
        if destination:
            clauses.append(f"(dst_ip = {self.bind} OR src_ip = {self.bind})")
            values.extend([destination, destination])
        if protocol:
            clauses.append(f"transport = {self.bind}")
            values.append(protocol)
        if min_bytes > 0:
            clauses.append(f"total_bytes >= {self.bind}")
            values.append(min_bytes)
        if start_ts is not None:
            clauses.append(f"last_seen >= {self.bind}")
            values.append(start_ts)
        if end_ts is not None:
            clauses.append(f"first_seen <= {self.bind}")
            values.append(end_ts)
        if artifact_only:
            clauses.append("extracted_artifact IS NOT NULL AND extracted_artifact != ''")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT json_blob FROM sessions {where} ORDER BY last_seen DESC LIMIT {self.bind}"
        values.append(limit)
        rows = self._fetchall(query, values)
        sessions = [json.loads(row["json_blob"]) for row in rows]
        if text_query:
            needle = text_query.lower()
            sessions = [row for row in sessions if needle in json.dumps(row).lower()]
        return sessions

    def fetch_session_detail(self, session_id: str) -> Optional[Dict[str, object]]:
        row = self._fetchone(
            f"SELECT json_blob FROM sessions WHERE session_id = {self.bind}",
            (session_id,),
        )
        if not row:
            return None
        session = json.loads(row["json_blob"])
        session["events"] = self.fetch_events_for_session(session_id, limit=120)
        session["alerts"] = self.fetch_alerts_for_session(session_id, limit=80)
        session["conversation"] = self._build_session_conversation(session, session["events"], session["alerts"])
        session["transcript"] = self._build_session_transcript(session["conversation"])
        return session

    def fetch_saved_hunts(self, limit: int = 100) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"SELECT name, dataset, notes, created_at, updated_at, query_json FROM saved_hunts ORDER BY updated_at DESC LIMIT {self.bind}",
            (limit,),
        )
        hunts: List[Dict[str, object]] = []
        for row in rows:
            hunts.append(
                {
                    "name": row.get("name", ""),
                    "dataset": row.get("dataset", "alerts"),
                    "notes": row.get("notes", ""),
                    "created_at": row.get("created_at", 0),
                    "updated_at": row.get("updated_at", 0),
                    "query": json.loads(row.get("query_json") or "{}"),
                }
            )
        return hunts

    def fetch_baseline(self, host: str) -> Dict[str, object]:
        row = self._fetchone(
            f"SELECT updated_at, json_blob FROM baselines WHERE host = {self.bind}",
            (host,),
        )
        if not row:
            return {"host": host, "updated_at": 0, "profile": {}, "available": False}
        return {
            "host": host,
            "updated_at": float(row.get("updated_at") or 0),
            "profile": json.loads(row.get("json_blob") or "{}"),
            "available": True,
        }

    def fetch_baseline_profiles(self, limit: int = 200) -> List[Dict[str, object]]:
        rows = self._fetchall(
            f"SELECT host, updated_at, json_blob FROM baselines ORDER BY updated_at DESC LIMIT {self.bind}",
            (limit,),
        )
        profiles: List[Dict[str, object]] = []
        for row in rows:
            payload = json.loads(row.get("json_blob") or "{}")
            profiles.append(
                {
                    "host": row.get("host", ""),
                    "updated_at": float(row.get("updated_at") or 0),
                    "top_destinations": payload.get("destinations", [])[:5],
                    "top_ports": payload.get("ports", [])[:5],
                    "top_protocols": payload.get("protocols", [])[:5],
                    "score": payload.get("score", 0),
                    "reputation_score": payload.get("reputation_score", 0),
                }
            )
        return profiles

    def fetch_artifacts(self, limit: int = 100) -> List[Dict[str, object]]:
        sessions = self.fetch_sessions(limit=max(limit, 200))
        artifacts: List[Dict[str, object]] = []
        for session in sessions:
            for artifact in session.get("artifacts", []):
                item = dict(artifact)
                item["session_id"] = session.get("session_id")
                item["src_ip"] = session.get("src_ip")
                item["dst_ip"] = session.get("dst_ip")
                item["conversation_summary"] = session.get("conversation_summary", "")
                artifacts.append(item)
        artifacts.sort(key=lambda item: float(item.get("timestamp", 0)), reverse=True)
        return artifacts[:limit]

    def fetch_time_series(self, table: str, hours: int = 24, bucket_minutes: int = 15) -> List[Dict[str, object]]:
        if table not in {"events", "alerts"}:
            raise ValueError("table must be 'events' or 'alerts'")
        cutoff = time.time() - max(1, hours) * 3600
        rows = self._fetchall(
            f"SELECT timestamp FROM {table} WHERE timestamp >= {self.bind} ORDER BY timestamp ASC",
            (cutoff,),
        )
        buckets: Dict[int, int] = defaultdict(int)
        size = max(1, bucket_minutes) * 60
        for row in rows:
            stamp = int(float(row["timestamp"]) // size * size)
            buckets[stamp] += 1
        return [
            {"bucket_ts": bucket, "count": buckets[bucket]}
            for bucket in sorted(buckets)
        ]

    def fetch_long_term_trends(self, days: int = 30, bucket_hours: int = 24) -> Dict[str, object]:
        cutoff = time.time() - max(1, days) * 86400
        bucket_seconds = max(1, bucket_hours) * 3600
        traffic_rows = self._fetchall(
            f"SELECT timestamp, src_ip FROM events WHERE timestamp >= {self.bind} ORDER BY timestamp ASC",
            (cutoff,),
        )
        alert_rows = self._fetchall(
            f"SELECT timestamp, severity, classification, host FROM alerts WHERE timestamp >= {self.bind} ORDER BY timestamp ASC",
            (cutoff,),
        )

        traffic_buckets: Dict[int, int] = defaultdict(int)
        alert_buckets: Dict[int, int] = defaultdict(int)
        severity_buckets: Dict[int, Counter] = defaultdict(Counter)
        classifications = Counter()
        hosts = Counter()

        for row in traffic_rows:
            stamp = int(float(row["timestamp"]) // bucket_seconds * bucket_seconds)
            traffic_buckets[stamp] += 1
        for row in alert_rows:
            stamp = int(float(row["timestamp"]) // bucket_seconds * bucket_seconds)
            alert_buckets[stamp] += 1
            severity_buckets[stamp][str(row.get("severity") or "LOW")] += 1
            classifications[str(row.get("classification") or "Unknown")] += 1
            hosts[str(row.get("host") or "Unknown")] += 1

        severity_rows = []
        for stamp in sorted(severity_buckets):
            counts = severity_buckets[stamp]
            severity_rows.append(
                {
                    "bucket_ts": stamp,
                    "LOW": counts.get("LOW", 0),
                    "MEDIUM": counts.get("MEDIUM", 0),
                    "HIGH": counts.get("HIGH", 0),
                    "CRITICAL": counts.get("CRITICAL", 0),
                }
            )

        return {
            "window_days": days,
            "bucket_hours": bucket_hours,
            "traffic": [{"bucket_ts": key, "count": traffic_buckets[key]} for key in sorted(traffic_buckets)],
            "alerts": [{"bucket_ts": key, "count": alert_buckets[key]} for key in sorted(alert_buckets)],
            "severity": severity_rows,
            "top_classifications": [
                {"classification": key, "total": value}
                for key, value in classifications.most_common(8)
            ],
            "top_hosts": [{"host": key, "total": value} for key, value in hosts.most_common(8)],
        }

    def fetch_host_activity_series(self, host: str, days: int = 14, bucket_hours: int = 24) -> Dict[str, object]:
        cutoff = time.time() - max(1, days) * 86400
        bucket_seconds = max(1, bucket_hours) * 3600
        event_rows = self._fetchall(
            f"SELECT timestamp FROM events WHERE timestamp >= {self.bind} AND (src_ip = {self.bind} OR dst_ip = {self.bind}) ORDER BY timestamp ASC",
            (cutoff, host, host),
        )
        alert_rows = self._fetchall(
            f"SELECT timestamp FROM alerts WHERE timestamp >= {self.bind} AND host = {self.bind} ORDER BY timestamp ASC",
            (cutoff, host),
        )
        event_buckets: Dict[int, int] = defaultdict(int)
        alert_buckets: Dict[int, int] = defaultdict(int)
        for row in event_rows:
            event_buckets[int(float(row["timestamp"]) // bucket_seconds * bucket_seconds)] += 1
        for row in alert_rows:
            alert_buckets[int(float(row["timestamp"]) // bucket_seconds * bucket_seconds)] += 1
        return {
            "window_days": days,
            "bucket_hours": bucket_hours,
            "events": [{"bucket_ts": key, "count": event_buckets[key]} for key in sorted(event_buckets)],
            "alerts": [{"bucket_ts": key, "count": alert_buckets[key]} for key in sorted(alert_buckets)],
        }

    def fetch_asset_inventory(self, limit: int = 200) -> List[Dict[str, object]]:
        summary_rows = self._fetchall(
            f"""
            SELECT src_ip, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen,
                   COUNT(*) AS packets, COALESCE(SUM(packet_len), 0) AS bytes, MAX(os_guess) AS os_guess
            FROM events
            GROUP BY src_ip
            ORDER BY last_seen DESC
            LIMIT {self.bind}
            """,
            (limit,),
        )
        if not summary_rows:
            return []

        hosts = [str(row["src_ip"]) for row in summary_rows if row.get("src_ip")]
        alert_index = {
            str(row["host"]): row
            for row in self._fetchall(
                "SELECT host, COUNT(*) AS alert_count, COALESCE(MAX(score), 0) AS max_score FROM alerts GROUP BY host"
            )
        }
        baseline_index = {
            item["host"]: item
            for item in self.fetch_baseline_profiles(limit=max(limit, 500))
        }

        placeholders = self._placeholders(len(hosts))
        event_rows = self._fetchall(
            f"SELECT src_ip, dst_ip, dst_port, category, hostname, direction, timestamp "
            f"FROM events WHERE src_ip IN ({placeholders}) ORDER BY timestamp DESC LIMIT {self.bind}",
            (*hosts, max(limit * 150, 5000)),
        )
        protocol_index: Dict[str, Counter] = defaultdict(Counter)
        port_index: Dict[str, Counter] = defaultdict(Counter)
        peer_index: Dict[str, Counter] = defaultdict(Counter)
        destination_index: Dict[str, Counter] = defaultdict(Counter)
        for row in event_rows:
            host = str(row.get("src_ip") or "")
            if not host:
                continue
            protocol_index[host][str(row.get("category") or "Unknown")] += 1
            port_index[host][int(row.get("dst_port") or 0)] += 1
            peer = str(row.get("dst_ip") or "")
            if peer:
                peer_index[host][peer] += 1
            destination = str(row.get("hostname") or row.get("dst_ip") or "")
            if destination:
                destination_index[host][destination] += 1

        assets: List[Dict[str, object]] = []
        for row in summary_rows:
            host = str(row.get("src_ip") or "")
            if not host:
                continue
            alerts = alert_index.get(host, {})
            baseline = baseline_index.get(host, {})
            protocols = protocol_index.get(host, Counter()).most_common(5)
            ports = port_index.get(host, Counter()).most_common(5)
            peers = peer_index.get(host, Counter()).most_common(5)
            destinations = destination_index.get(host, Counter()).most_common(5)
            assets.append(
                {
                    "host": host,
                    "role": "Internal asset" if _is_private_ip(host) else "External source",
                    "first_seen": float(row.get("first_seen") or 0),
                    "last_seen": float(row.get("last_seen") or 0),
                    "packets": int(row.get("packets") or 0),
                    "bytes": int(row.get("bytes") or 0),
                    "os_guess": row.get("os_guess") or "Unknown",
                    "alert_count": int(alerts.get("alert_count") or 0),
                    "max_score": int(alerts.get("max_score") or 0),
                    "baseline_ready": bool(baseline),
                    "top_protocols": [{"name": key, "total": value} for key, value in protocols],
                    "top_ports": [{"port": key, "total": value} for key, value in ports],
                    "top_peers": [{"peer": key, "total": value} for key, value in peers],
                    "top_destinations": [{"destination": key, "total": value} for key, value in destinations],
                    "baseline_updated_at": float(baseline.get("updated_at") or 0),
                }
            )
        assets.sort(key=lambda item: (item["alert_count"], item["packets"], item["last_seen"]), reverse=True)
        return assets[:limit]

    def fetch_hunt_summary(self, hours: int = 24) -> Dict[str, object]:
        cutoff = time.time() - max(1, hours) * 3600
        alerts = self.search_alerts(limit=500)
        recent_alerts = [alert for alert in alerts if float(alert.get("timestamp", 0)) >= cutoff]
        by_classification = Counter(alert.get("classification", "Unknown") for alert in recent_alerts)
        by_technique = Counter(alert.get("mitre_technique", "Unknown") for alert in recent_alerts)
        return {
            "window_hours": hours,
            "total_recent_alerts": len(recent_alerts),
            "top_classifications": [
                {"classification": key, "total": value}
                for key, value in by_classification.most_common(10)
            ],
            "top_techniques": [
                {"technique": key, "total": value}
                for key, value in by_technique.most_common(10)
            ],
        }

    def fetch_host_detail(self, host: str, limit: int = 200) -> Dict[str, object]:
        alerts = self.search_alerts(host=host, limit=limit)
        events = self.search_events(host=host, limit=limit)
        sessions = self.search_sessions(host=host, limit=limit)
        inventory = next(
            (item for item in self.fetch_asset_inventory(limit=max(limit, 500)) if item["host"] == host),
            None,
        )
        return {
            "host": host,
            "inventory": inventory or {"host": host},
            "baseline": self.fetch_baseline(host),
            "activity_series": self.fetch_host_activity_series(host),
            "alerts": alerts,
            "events": events,
            "sessions": sessions,
        }

    def close(self) -> None:
        self.connection.close()


def create_store(database_path: str, storage_backend: str = "auto") -> DatabaseStore:
    backend = (storage_backend or "auto").lower()
    if backend in {"sqlalchemy", "orm"} or _is_sqlalchemy_target(database_path):
        from .orm_storage import SQLAlchemyStore

        return SQLAlchemyStore(database_path)
    return DatabaseStore(database_path)


SQLiteStore = DatabaseStore

