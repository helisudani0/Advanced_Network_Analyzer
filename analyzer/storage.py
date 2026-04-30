from __future__ import annotations

import json
import sqlite3
import threading
from typing import Dict, List

from .models import AlertRecord, HostSnapshot, PacketContext, SessionRecord


class SQLiteStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        self.lock = threading.Lock()
        self.connection = sqlite3.connect(database_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        cursor = self.connection.cursor()
        cursor.executescript(
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
            );

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
            );

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
            );

            CREATE TABLE IF NOT EXISTS baselines (
                host TEXT PRIMARY KEY,
                updated_at REAL,
                json_blob TEXT
            );
            """
        )
        self.connection.commit()

    def insert_event(self, context: PacketContext) -> None:
        payload = context.to_dict()
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO events (
                    timestamp, src_ip, dst_ip, src_port, dst_port, transport, category,
                    hostname, base_domain, geo, direction, packet_len, session_id,
                    payload_preview, user_agent, http_url, tls_version, tls_sni, os_guess,
                    risk_score, risk_factors_json, json_blob
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                ),
            )
            self.connection.commit()

    def insert_alert(self, alert: AlertRecord) -> None:
        payload = alert.to_dict()
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO alerts (
                    timestamp, host, destination, severity, title, classification, score,
                    reasons_json, action, mitre_technique, mitre_tactic, geo, iocs_json,
                    dedupe_key, occurrences, recommended_block, session_id, json_blob
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                ),
            )
            self.connection.commit()

    def upsert_session(self, session: SessionRecord) -> None:
        payload = session.to_dict()
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO sessions (
                    session_id, src_ip, dst_ip, src_port, dst_port, transport, first_seen,
                    last_seen, packet_count, total_bytes, protocol_hints_json, snippets_json,
                    extracted_artifact, json_blob
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    packet_count=excluded.packet_count,
                    total_bytes=excluded.total_bytes,
                    protocol_hints_json=excluded.protocol_hints_json,
                    snippets_json=excluded.snippets_json,
                    extracted_artifact=excluded.extracted_artifact,
                    json_blob=excluded.json_blob
                """,
                (
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
                ),
            )
            self.connection.commit()

    def upsert_baseline(self, host: str, updated_at: float, payload: Dict[str, object]) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO baselines (host, updated_at, json_blob)
                VALUES (?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    json_blob=excluded.json_blob
                """,
                (host, updated_at, json.dumps(payload)),
            )
            self.connection.commit()

    def fetch_alerts(self, limit: int = 100) -> List[Dict[str, object]]:
        cursor = self.connection.execute(
            "SELECT json_blob FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [json.loads(row["json_blob"]) for row in cursor.fetchall()]

    def fetch_top_riskiest(self, limit: int = 10) -> List[Dict[str, object]]:
        cursor = self.connection.execute(
            """
            SELECT host, MAX(score) AS max_score, COUNT(*) AS alert_count
            FROM alerts
            GROUP BY host
            ORDER BY max_score DESC, alert_count DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def fetch_mitre_heatmap(self) -> List[Dict[str, object]]:
        cursor = self.connection.execute(
            """
            SELECT mitre_tactic, mitre_technique, COUNT(*) AS total
            FROM alerts
            GROUP BY mitre_tactic, mitre_technique
            ORDER BY total DESC
            """
        )
        return [dict(row) for row in cursor.fetchall()]

    def fetch_alert_counts(self) -> Dict[str, int]:
        cursor = self.connection.execute(
            "SELECT severity, COUNT(*) AS total FROM alerts GROUP BY severity"
        )
        return {row["severity"]: row["total"] for row in cursor.fetchall()}

    def fetch_sessions(self, limit: int = 100) -> List[Dict[str, object]]:
        cursor = self.connection.execute(
            "SELECT json_blob FROM sessions ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        )
        return [json.loads(row["json_blob"]) for row in cursor.fetchall()]

    def fetch_events(self, limit: int = 200) -> List[Dict[str, object]]:
        cursor = self.connection.execute(
            "SELECT json_blob FROM events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return [json.loads(row["json_blob"]) for row in cursor.fetchall()]

    def close(self) -> None:
        self.connection.close()
