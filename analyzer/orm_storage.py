from __future__ import annotations

import json
import threading
import time
from typing import Dict, Iterable, List, Optional

from .models import AlertRecord, PacketContext, SessionRecord
from .storage import DatabaseStore


try:
    from sqlalchemy import BigInteger, Column, Float, Integer, Text, create_engine
    from sqlalchemy.orm import declarative_base, sessionmaker
except Exception:
    BigInteger = None
    Column = None
    Float = None
    Integer = None
    Text = None
    create_engine = None
    declarative_base = None
    sessionmaker = None


Base = declarative_base() if declarative_base is not None else None


if Base is not None:
    class EventRow(Base):
        __tablename__ = "events"

        id = Column(Integer, primary_key=True, autoincrement=True)
        timestamp = Column(Float)
        src_ip = Column(Text)
        dst_ip = Column(Text)
        src_port = Column(Integer)
        dst_port = Column(Integer)
        transport = Column(Text)
        category = Column(Text)
        hostname = Column(Text)
        base_domain = Column(Text)
        geo = Column(Text)
        direction = Column(Text)
        packet_len = Column(Integer)
        session_id = Column(Text)
        payload_preview = Column(Text)
        user_agent = Column(Text)
        http_url = Column(Text)
        tls_version = Column(Text)
        tls_sni = Column(Text)
        os_guess = Column(Text)
        risk_score = Column(Integer)
        risk_factors_json = Column(Text)
        json_blob = Column(Text)


    class AlertRow(Base):
        __tablename__ = "alerts"

        id = Column(Integer, primary_key=True, autoincrement=True)
        timestamp = Column(Float)
        host = Column(Text)
        destination = Column(Text)
        severity = Column(Text)
        title = Column(Text)
        classification = Column(Text)
        score = Column(Integer)
        reasons_json = Column(Text)
        action = Column(Text)
        mitre_technique = Column(Text)
        mitre_tactic = Column(Text)
        geo = Column(Text)
        iocs_json = Column(Text)
        dedupe_key = Column(Text)
        occurrences = Column(Integer)
        recommended_block = Column(Text)
        session_id = Column(Text)
        json_blob = Column(Text)


    class SessionRow(Base):
        __tablename__ = "sessions"

        session_id = Column(Text, primary_key=True)
        src_ip = Column(Text)
        dst_ip = Column(Text)
        src_port = Column(Integer)
        dst_port = Column(Integer)
        transport = Column(Text)
        first_seen = Column(Float)
        last_seen = Column(Float)
        packet_count = Column(Integer)
        total_bytes = Column(BigInteger)
        protocol_hints_json = Column(Text)
        snippets_json = Column(Text)
        extracted_artifact = Column(Text)
        json_blob = Column(Text)


    class BaselineRow(Base):
        __tablename__ = "baselines"

        host = Column(Text, primary_key=True)
        updated_at = Column(Float)
        json_blob = Column(Text)


    class SavedHuntRow(Base):
        __tablename__ = "saved_hunts"

        id = Column(Integer, primary_key=True, autoincrement=True)
        name = Column(Text, unique=True)
        dataset = Column(Text)
        notes = Column(Text)
        created_at = Column(Float)
        updated_at = Column(Float)
        query_json = Column(Text)


def _normalize_url(database_path: str) -> str:
    if database_path.startswith("sqlalchemy+"):
        return database_path[len("sqlalchemy+"):]
    if database_path.startswith("postgresql://") or database_path.startswith("postgres://"):
        return database_path
    if "://" in database_path:
        return database_path
    return f"sqlite:///{database_path}"


class SQLAlchemyStore(DatabaseStore):
    """SQLAlchemy ORM-backed store with the same query surface as DatabaseStore."""

    def __init__(self, database_path: str):
        if create_engine is None or Base is None or sessionmaker is None:
            raise RuntimeError("SQLAlchemy storage requires the 'sqlalchemy' package.")
        self.database_path = _normalize_url(database_path)
        self.backend = "sqlalchemy"
        self.lock = threading.Lock()
        self.engine = create_engine(self.database_path, future=True, pool_pre_ping=True)
        self.driver = self.engine.dialect.name
        self.bind = "%s" if self.driver.startswith("postgres") else "?"
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, future=True, expire_on_commit=False)
        self.connection = self.engine.raw_connection()

    def _execute(self, query: str, values: Iterable[object] = ()) -> None:
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute(query, tuple(values))
            self.connection.commit()
            cursor.close()

    def _fetchall(self, query: str, values: Iterable[object] = ()) -> List[Dict[str, object]]:
        with self.lock:
            cursor = self.connection.cursor()
            cursor.execute(query, tuple(values))
            rows = cursor.fetchall()
            columns = [column[0] for column in (cursor.description or [])]
            cursor.close()
        return [dict(zip(columns, row)) for row in rows]

    def insert_event(self, context: PacketContext) -> None:
        payload = context.to_dict()
        with self.SessionLocal() as session:
            session.add(
                EventRow(
                    timestamp=context.timestamp,
                    src_ip=context.src_ip,
                    dst_ip=context.dst_ip,
                    src_port=context.src_port,
                    dst_port=context.dst_port,
                    transport=context.transport,
                    category=context.category,
                    hostname=context.hostname,
                    base_domain=context.base_domain,
                    geo=context.geo,
                    direction=context.direction,
                    packet_len=context.packet_len,
                    session_id=context.session_id,
                    payload_preview=context.payload_preview,
                    user_agent=context.http_user_agent,
                    http_url=context.http_url,
                    tls_version=context.tls_version,
                    tls_sni=context.tls_sni,
                    os_guess=context.os_guess,
                    risk_score=context.risk_score,
                    risk_factors_json=json.dumps(context.risk_factors),
                    json_blob=json.dumps(payload),
                )
            )
            session.commit()

    def insert_alert(self, alert: AlertRecord) -> None:
        payload = alert.to_dict()
        with self.SessionLocal() as session:
            session.add(
                AlertRow(
                    timestamp=alert.timestamp,
                    host=alert.host,
                    destination=alert.destination,
                    severity=alert.severity,
                    title=alert.title,
                    classification=alert.classification,
                    score=alert.score,
                    reasons_json=json.dumps(alert.reasons),
                    action=alert.action,
                    mitre_technique=alert.mitre_technique,
                    mitre_tactic=alert.mitre_tactic,
                    geo=alert.geo,
                    iocs_json=json.dumps(alert.iocs),
                    dedupe_key=alert.dedupe_key,
                    occurrences=alert.occurrences,
                    recommended_block=alert.recommended_block,
                    session_id=alert.session_id,
                    json_blob=json.dumps(payload),
                )
            )
            session.commit()

    def upsert_session(self, session_record: SessionRecord) -> None:
        payload = session_record.to_dict()
        with self.SessionLocal() as session:
            row = SessionRow(
                session_id=session_record.session_id,
                src_ip=session_record.src_ip,
                dst_ip=session_record.dst_ip,
                src_port=session_record.src_port,
                dst_port=session_record.dst_port,
                transport=session_record.transport,
                first_seen=session_record.first_seen,
                last_seen=session_record.last_seen,
                packet_count=session_record.packet_count,
                total_bytes=session_record.total_bytes,
                protocol_hints_json=json.dumps(session_record.protocol_hints),
                snippets_json=json.dumps(session_record.snippets),
                extracted_artifact=session_record.extracted_artifact,
                json_blob=json.dumps(payload),
            )
            session.merge(row)
            session.commit()

    def upsert_baseline(self, host: str, updated_at: float, payload: Dict[str, object]) -> None:
        with self.SessionLocal() as session:
            session.merge(BaselineRow(host=host, updated_at=updated_at, json_blob=json.dumps(payload)))
            session.commit()

    def save_hunt_query(self, name: str, dataset: str, query: Dict[str, object], notes: str = "") -> None:
        now = time.time()
        with self.SessionLocal() as session:
            row = session.query(SavedHuntRow).filter(SavedHuntRow.name == name).one_or_none()
            if row is None:
                row = SavedHuntRow(name=name, created_at=now)
                session.add(row)
            row.dataset = dataset
            row.notes = notes
            row.updated_at = now
            row.query_json = json.dumps(query)
            session.commit()

    def close(self) -> None:
        try:
            self.connection.close()
        finally:
            self.engine.dispose()
