from __future__ import annotations

from typing import Optional

from .storage import SQLiteStore

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except Exception:
    FastAPI = None
    HTTPException = Exception
    BaseModel = object


class ReplayRequest(BaseModel):
    pcap_path: str
    playback_speed: float = 0.0


def create_api(store: SQLiteStore, platform=None):
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed. Install requirements to enable the API server.")

    app = FastAPI(title="Advanced Network Threat Detection API", version="1.0")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/alerts")
    def list_alerts(limit: int = 100):
        return {"alerts": store.fetch_alerts(limit=limit)}

    @app.get("/events")
    def list_events(limit: int = 200):
        return {"events": store.fetch_events(limit=limit)}

    @app.get("/sessions")
    def list_sessions(limit: int = 100):
        return {"sessions": store.fetch_sessions(limit=limit)}

    @app.get("/mitre")
    def mitre():
        return {"coverage": store.fetch_mitre_heatmap()}

    @app.get("/top-risky")
    def top_risky(limit: int = 10):
        return {"connections": store.fetch_top_riskiest(limit=limit)}

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
