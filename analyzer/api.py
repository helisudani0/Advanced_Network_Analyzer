from __future__ import annotations

import json
import time
from pathlib import Path

from .app_ui import render_launcher_html, render_site_html
from .models import AlertRecord
from .output import to_cef
from .reporting import list_pdf_reports
from .storage import SQLiteStore

try:
    from fastapi import Body, FastAPI, File, HTTPException, UploadFile
    from fastapi.responses import FileResponse, HTMLResponse, Response
    from pydantic import BaseModel
except Exception:
    Body = None
    File = None
    FastAPI = None
    HTTPException = Exception
    FileResponse = object
    HTMLResponse = object
    Response = object
    UploadFile = object
    BaseModel = object


class ReplayRequest(BaseModel):
    pcap_path: str
    playback_speed: float = 0.0


class SavedHuntRequest(BaseModel):
    name: str
    dataset: str = "alerts"
    query: dict
    notes: str = ""


class AppSettingsRequest(BaseModel):
    interfaces: str = ""
    quick_filter: str = "all"
    bpf_filter: str = ""
    dashboard_refresh_seconds: int = 5
    worker_count: int = 2
    geoip_db: str = ""
    ioc_sources: str = ""
    ml_enabled: bool = True
    sequence_model_enabled: bool = True
    lstm_enabled: bool = False
    packet_parser: str = "scapy"


def create_api(store: SQLiteStore, platform=None):
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed. Install requirements to enable the API server.")

    app = FastAPI(title="Ravynel NDR API", version="1.0")

    def current_summary():
        if platform is not None:
            return platform.summary()
        return {
            "alerts_generated": len(store.fetch_alerts(limit=1000)),
            "tracked_hosts": len(store.fetch_top_riskiest(limit=100)),
            "tracked_sessions": len(store.fetch_sessions(limit=1000)),
            "packets_processed": len(store.fetch_events(limit=1000)),
            "ioc_count": 0,
            "database_backend": getattr(store, "backend", "sqlite"),
            "database_driver": getattr(store, "driver", "sqlite3"),
            "database_target": getattr(store, "database_path", "analyzer.db"),
            "geoip_status": "Historical database view",
        }

    def launcher_snapshot():
        summary = current_summary()
        settings = platform.launcher_settings() if platform is not None else {
            "interfaces": [],
            "bpf_filter": "",
            "quick_filter": "all",
            "geoip_db": "",
            "dashboard_refresh_seconds": 5,
            "worker_count": 2,
            "ioc_sources": [],
            "database_path": getattr(store, "database_path", "analyzer.db"),
            "storage_backend": getattr(store, "backend", "sqlite"),
            "packet_parser": "scapy",
            "report_dir": "reports",
            "ml_enabled": True,
            "sequence_model_enabled": True,
            "lstm_enabled": False,
        }
        report_dir = settings.get("report_dir") or "reports"
        return {
            "summary": summary,
            "capture_active": platform.capture_active() if platform is not None else False,
            "capture_error": getattr(platform, "last_capture_error", "") if platform is not None else "",
            "settings": settings,
            "recent_alerts": store.fetch_alerts(limit=10),
            "saved_hunts": store.fetch_saved_hunts(limit=12),
            "reports": list_pdf_reports(str(report_dir)),
            "feed_status": platform.feed_status() if platform is not None else [],
            "model_status": platform.model_status() if platform is not None else {
                "isolation_forest": "Historical database view",
                "sequence_model": "Historical database view",
            },
        }

    @app.get("/", response_class=HTMLResponse)
    def root():
        return render_site_html()

    @app.get("/app", response_class=HTMLResponse)
    def app_launcher():
        return render_launcher_html()

    @app.get("/health")
    def health():
        return {"status": "ok"}


    @app.get("/summary")
    def summary():
        return current_summary()

    @app.get("/app-data")
    def app_data():
        return launcher_snapshot()

    @app.post("/app/settings")
    def save_app_settings(request: AppSettingsRequest):
        if platform is None:
            raise HTTPException(status_code=503, detail="Runtime settings are only available while the platform is running.")
        return platform.update_settings(
            {
                "interfaces": request.interfaces,
                "quick_filter": request.quick_filter,
                "bpf_filter": request.bpf_filter,
                "dashboard_refresh_seconds": request.dashboard_refresh_seconds,
                "worker_count": request.worker_count,
                "geoip_db": request.geoip_db,
                "ioc_sources": request.ioc_sources,
                "ml_enabled": request.ml_enabled,
                "sequence_model_enabled": request.sequence_model_enabled,
                "lstm_enabled": request.lstm_enabled,
                "packet_parser": request.packet_parser,
            }
        )

    @app.post("/app/profile/{profile_name}")
    def apply_app_profile(profile_name: str):
        if platform is None:
            raise HTTPException(status_code=503, detail="Runtime profile changes require the running platform.")
        try:
            return platform.apply_profile(profile_name)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/intel/feeds")
    def intel_feeds():
        if platform is None:
            return {"feeds": []}
        return {"feeds": platform.feed_status()}

    @app.post("/intel/refresh")
    def refresh_intel():
        if platform is None:
            raise HTTPException(status_code=503, detail="Threat feed refresh requires the running platform.")
        platform.intel.load_all()
        return {"status": "refreshed", "feeds": platform.feed_status()}

    @app.post("/capture/start")
    def start_capture():
        if platform is None:
            raise HTTPException(status_code=503, detail="Live capture controls require the running platform.")
        try:
            if platform.capture_active():
                return {
                    "status": "running",
                    "capture_active": True,
                    "message": "Live packet capture is already running.",
                }
            before = platform.packet_count
            platform.start_live_capture()
            deadline = time.time() + 1.6
            stable_since = None
            while time.time() < deadline:
                if getattr(platform, "last_capture_error", ""):
                    break
                if platform.capture_active():
                    if stable_since is None:
                        stable_since = time.time()
                    if time.time() - stable_since >= 0.35:
                        return {
                            "status": "started",
                            "capture_active": True,
                            "message": "Live packet capture is running.",
                        }
                else:
                    stable_since = None
                time.sleep(0.05)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        detail = getattr(platform, "last_capture_error", "") or "Capture did not remain active. Check Npcap, administrator permissions, adapter name, and BPF filter."
        if platform.packet_count > before:
            detail = "Packets were observed, but the capture thread stopped unexpectedly. " + detail
        raise HTTPException(status_code=503, detail=detail)

    @app.post("/capture/stop")
    def stop_capture():
        if platform is None:
            raise HTTPException(status_code=503, detail="Live capture controls require the running platform.")
        was_active = platform.capture_active()
        platform.stop_capture()
        response = {"status": "stopped", "message": "Capture stopped."}
        if was_active and (platform.packet_count > 0 or platform.alert_count > 0):
            response["report"] = platform.generate_reports().get("pdf", "")
            response["message"] = "Capture stopped and a PDF report was saved to the report vault."
        return response

    @app.post("/remote/ingest/context")
    def remote_ingest_context(request: dict = Body(...)):
        if platform is None:
            raise HTTPException(status_code=503, detail="Remote ingestion requires the running platform.")
        try:
            return platform.ingest_remote_context(request)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/remote/ingest/batch")
    def remote_ingest_batch(request: dict = Body(...)):
        if platform is None:
            raise HTTPException(status_code=503, detail="Remote ingestion requires the running platform.")
        events = request.get("events", [])
        if not isinstance(events, list):
            raise HTTPException(status_code=400, detail="events must be a list")
        results = []
        for item in events:
            if not isinstance(item, dict):
                continue
            try:
                results.append(platform.ingest_remote_context(item))
            except Exception as exc:
                results.append({"status": "error", "detail": str(exc)})
        return {"ingested": len([row for row in results if row.get("status") == "ingested"]), "results": results}

    @app.post("/remote/ingest/raw")
    def remote_ingest_raw(request: dict = Body(...)):
        if platform is None:
            raise HTTPException(status_code=503, detail="Remote raw-packet ingestion requires the running platform.")
        try:
            return platform.ingest_remote_raw_packet(request)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.get("/reports/list")
    def report_list():
        return {"reports": launcher_snapshot()["reports"]}

    @app.post("/reports/generate")
    def generate_report():
        if platform is None:
            raise HTTPException(status_code=503, detail="Report generation requires the running platform.")
        path = platform.generate_reports().get("pdf", "")
        return {"status": "generated", "message": "PDF report generated.", "path": path}

    @app.get("/benchmark/ingest")
    def benchmark_ingest_get(sample_count: int = 0):
        if platform is None:
            raise HTTPException(status_code=503, detail="Ingest benchmarking requires the running platform.")
        return platform.benchmark_ingest(sample_count or None)

    @app.post("/benchmark/ingest")
    def benchmark_ingest_post(request: dict = Body(default=None)):
        if platform is None:
            raise HTTPException(status_code=503, detail="Ingest benchmarking requires the running platform.")
        payload = request or {}
        return platform.benchmark_ingest(payload.get("sample_count"))

    @app.get("/exports/iocs")
    def export_iocs():
        indicators = sorted(
            {
                indicator
                for alert in store.fetch_alerts(limit=5000)
                for indicator in alert.get("iocs", []) or []
                if indicator
            }
        )
        payload = "\n".join(indicators)
        headers = {"Content-Disposition": 'attachment; filename="observed-iocs.txt"'}
        return Response(content=payload, media_type="text/plain; charset=utf-8", headers=headers)

    @app.get("/exports/cef")
    def export_cef():
        alerts = []
        for payload in store.fetch_alerts(limit=5000):
            alerts.append(
                AlertRecord(
                    timestamp=float(payload.get("timestamp", 0)),
                    host=str(payload.get("host", "")),
                    destination=str(payload.get("destination", "")),
                    severity=str(payload.get("severity", "LOW")),
                    title=str(payload.get("title", "")),
                    classification=str(payload.get("classification", "")),
                    score=int(payload.get("score", 0)),
                    reasons=[str(item) for item in payload.get("reasons", []) or []],
                    action=str(payload.get("action", "")),
                    mitre_technique=str(payload.get("mitre_technique", "")),
                    mitre_tactic=str(payload.get("mitre_tactic", "")),
                    geo=str(payload.get("geo", "")),
                    iocs=[str(item) for item in payload.get("iocs", []) or []],
                    dedupe_key=str(payload.get("dedupe_key", "")),
                    occurrences=int(payload.get("occurrences", 1) or 1),
                    recommended_block=str(payload.get("recommended_block", "")),
                    session_id=str(payload.get("session_id", "")),
                )
            )
        payload = "\n".join(to_cef(alert) for alert in alerts)
        headers = {"Content-Disposition": 'attachment; filename="alerts.cef"'}
        return Response(content=payload, media_type="text/plain; charset=utf-8", headers=headers)

    @app.get("/exports/jsonl")
    def export_jsonl():
        payload = "\n".join(json.dumps(alert) for alert in store.fetch_alerts(limit=5000))
        headers = {"Content-Disposition": 'attachment; filename="alerts.jsonl"'}
        return Response(content=payload, media_type="application/x-ndjson; charset=utf-8", headers=headers)

    @app.post("/pcap/upload")
    async def upload_pcap(file: UploadFile = File(...), playback_speed: float = 0.0):
        if platform is None:
            raise HTTPException(status_code=503, detail="PCAP upload requires the running platform.")
        upload_dir = Path("uploads")
        upload_dir.mkdir(parents=True, exist_ok=True)
        target = upload_dir / Path(file.filename or "capture.pcap").name
        content = await file.read()
        target.write_bytes(content)
        try:
            platform.replay_pcap(str(target), playback_speed)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "processed", "pcap_path": str(target)}

    @app.get("/reports/file/{name}")
    def report_file(name: str):
        report_dir = Path((platform.config.report_dir if platform is not None else "reports")).resolve()
        target = (report_dir / name).resolve()
        if report_dir != target.parent:
            raise HTTPException(status_code=400, detail="Invalid report path")
        if not target.exists() or target.suffix.lower() != ".pdf":
            raise HTTPException(status_code=404, detail="Report not found")
        return FileResponse(str(target), media_type="application/pdf", filename=target.name)

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard():
        return render_launcher_html()

    @app.get("/dashboard/assets", response_class=HTMLResponse)
    def dashboard_assets():
        return render_launcher_html()

    @app.get("/dashboard/assets/{host_ip:path}", response_class=HTMLResponse)
    def dashboard_asset_detail(host_ip: str):
        return render_launcher_html()

    @app.get("/dashboard/baselines", response_class=HTMLResponse)
    def dashboard_baselines():
        return render_launcher_html()

    @app.get("/dashboard/baselines/{host_ip:path}", response_class=HTMLResponse)
    def dashboard_baseline_detail(host_ip: str):
        return render_launcher_html()

    @app.get("/dashboard/hunts", response_class=HTMLResponse)
    def dashboard_hunts():
        return render_launcher_html()

    @app.get("/dashboard-data")
    def dashboard_data():
        if platform is not None:
            return platform.dashboard_snapshot()
        assets = store.fetch_asset_inventory(limit=200)
        return {
            "summary": summary(),
            "severity_counts": store.fetch_alert_counts(),
            "protocol_distribution": store.fetch_protocol_distribution(),
            "top_talkers": store.fetch_top_talkers(),
            "geo_summary": store.fetch_geo_summary(),
            "top_risky": store.fetch_top_riskiest(),
            "mitre_heatmap": store.fetch_mitre_heatmap(),
            "alerts": store.fetch_alerts(limit=30),
            "timeline": store.fetch_alert_timeline(limit=40),
            "sessions": store.fetch_sessions(limit=20),
            "hosts": [
                {
                    "ip": asset.get("host", ""),
                    "severity": "HIGH" if int(asset.get("max_score", 0)) >= 20 else "MEDIUM" if int(asset.get("alert_count", 0)) >= 5 else "LOW",
                    "score": int(asset.get("max_score", 0)),
                    "packet_count": int(asset.get("packets", 0)),
                    "top_destination": ", ".join(item.get("destination", "") for item in asset.get("top_destinations", [])[:2]) or "-",
                    "last_finding": f"{asset.get('alert_count', 0)} stored alerts",
                }
                for asset in assets[:20]
            ],
            "topology": [
                {
                    "source": session.get("src_ip", ""),
                    "target": session.get("dst_ip", ""),
                    "label": f"{session.get('transport', '')}:{session.get('dst_port', '')}",
                    "bytes": session.get("total_bytes", 0),
                }
                for session in store.fetch_sessions(limit=12)
            ],
            "traffic_series": store.fetch_time_series("events"),
            "alert_series": store.fetch_time_series("alerts"),
            "artifacts": store.fetch_artifacts(limit=30),
            "hunt_summary": store.fetch_hunt_summary(),
            "asset_inventory": assets,
            "baseline_profiles": store.fetch_baseline_profiles(limit=200),
            "saved_hunts": store.fetch_saved_hunts(limit=50),
            "long_term_trends": store.fetch_long_term_trends(days=30),
            "live_capture_active": False,
            "capture_error": "",
            "dashboard_refresh_seconds": 5,
        }

    @app.get("/alerts")
    def list_alerts(limit: int = 100):
        return {"alerts": store.fetch_alerts(limit=limit)}

    @app.get("/alerts/search")
    def search_alerts(
        classification: str = "",
        severity: str = "",
        technique: str = "",
        host: str = "",
        destination: str = "",
        text_query: str = "",
        start_ts: float | None = None,
        end_ts: float | None = None,
        limit: int = 200,
    ):
        return {
            "alerts": store.search_alerts(
                classification=classification,
                severity=severity,
                technique=technique,
                host=host,
                destination=destination,
                text_query=text_query,
                start_ts=start_ts,
                end_ts=end_ts,
                limit=limit,
            )
        }

    @app.get("/events")
    def list_events(limit: int = 200):
        return {"events": store.fetch_events(limit=limit)}

    @app.get("/sessions")
    def list_sessions(limit: int = 100):
        return {"sessions": store.fetch_sessions(limit=limit)}

    @app.get("/sessions/{session_id}")
    def session_detail(session_id: str):
        detail = store.fetch_session_detail(session_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Session not found")
        return detail

    @app.get("/mitre")
    def mitre():
        return {"coverage": store.fetch_mitre_heatmap()}

    @app.get("/top-risky")
    def top_risky(limit: int = 10):
        return {"connections": store.fetch_top_riskiest(limit=limit)}

    @app.get("/protocols")
    def protocols():
        return {"protocols": store.fetch_protocol_distribution()}

    @app.get("/geo")
    def geo():
        return {"geos": store.fetch_geo_summary()}

    @app.get("/timeline")
    def timeline(limit: int = 100):
        return {"timeline": store.fetch_alert_timeline(limit=limit)}

    @app.get("/artifacts")
    def artifacts(limit: int = 100):
        return {"artifacts": store.fetch_artifacts(limit=limit)}

    @app.get("/inventory/assets")
    def asset_inventory(limit: int = 200):
        return {"assets": store.fetch_asset_inventory(limit=limit)}

    @app.get("/baselines")
    def baselines(limit: int = 200):
        return {"baselines": store.fetch_baseline_profiles(limit=limit)}

    @app.get("/baselines/{host_ip}")
    def baseline_detail(host_ip: str):
        return store.fetch_baseline(host_ip)

    @app.get("/series/traffic")
    def traffic_series(hours: int = 24, bucket_minutes: int = 15):
        return {"series": store.fetch_time_series("events", hours=hours, bucket_minutes=bucket_minutes)}

    @app.get("/series/alerts")
    def alerts_series(hours: int = 24, bucket_minutes: int = 15):
        return {"series": store.fetch_time_series("alerts", hours=hours, bucket_minutes=bucket_minutes)}

    @app.get("/hunt/summary")
    def hunt_summary(hours: int = 24):
        return store.fetch_hunt_summary(hours=hours)

    @app.get("/hunt/saved")
    def saved_hunts(limit: int = 100):
        return {"saved_hunts": store.fetch_saved_hunts(limit=limit)}

    @app.post("/hunt/saved")
    def save_hunt(request: dict = Body(...)):
        name = str(request.get("name", "")).strip()
        if not name:
            raise HTTPException(status_code=400, detail="Playbook name is required.")
        dataset = str(request.get("dataset", "alerts") or "alerts")
        query = request.get("query")
        notes = str(request.get("notes", "") or "")
        if not isinstance(query, dict):
            query = {}
        store.save_hunt_query(name, dataset, query, notes)
        return {"status": "saved", "name": name}

    @app.delete("/hunt/saved/{name}")
    def delete_saved_hunt(name: str):
        store.delete_saved_hunt_query(name)
        return {"status": "deleted", "name": name}

    @app.get("/hunt/events")
    def hunt_events(
        host: str = "",
        destination: str = "",
        protocol: str = "",
        domain: str = "",
        text_query: str = "",
        start_ts: float | None = None,
        end_ts: float | None = None,
        limit: int = 200,
    ):
        return {
            "events": store.search_events(
                host=host,
                destination=destination,
                protocol=protocol,
                domain=domain,
                text_query=text_query,
                start_ts=start_ts,
                end_ts=end_ts,
                limit=limit,
            )
        }

    @app.get("/hunt/sessions")
    def hunt_sessions(
        host: str = "",
        destination: str = "",
        protocol: str = "",
        artifact_only: bool = False,
        min_bytes: int = 0,
        text_query: str = "",
        start_ts: float | None = None,
        end_ts: float | None = None,
        limit: int = 200,
    ):
        return {
            "sessions": store.search_sessions(
                host=host,
                destination=destination,
                protocol=protocol,
                artifact_only=artifact_only,
                min_bytes=min_bytes,
                text_query=text_query,
                start_ts=start_ts,
                end_ts=end_ts,
                limit=limit,
            )
        }

    @app.get("/hosts/{host_ip}")
    def host_detail(host_ip: str, limit: int = 200):
        return store.fetch_host_detail(host_ip, limit=limit)

    @app.get("/trends/long-term")
    def long_term_trends(days: int = 30, bucket_hours: int = 24):
        return store.fetch_long_term_trends(days=days, bucket_hours=bucket_hours)

    if platform is not None:
        @app.get("/hosts")
        def hosts():
            return {"hosts": [row.to_dict() for row in platform.snapshot_hosts()]}

        @app.post("/pcap/replay")
        def replay(request: ReplayRequest):
            try:
                platform.replay_pcap(request.pcap_path, request.playback_speed)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            return {"status": "started", "pcap_path": request.pcap_path}

    return app
