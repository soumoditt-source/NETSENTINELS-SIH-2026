"""Standalone NetSentinel Plus console.

This sidecar reads the existing NetSentinel API and adds optional enrichment
without importing or modifying the existing application startup path.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from addons.netsentinel_plus.assessment import build_temporal_assessment
from addons.netsentinel_plus.providers import ProviderService


ROOT = Path(__file__).resolve().parent
BACKEND_URL = os.getenv("NETSENTINEL_BACKEND_URL", "http://127.0.0.1:8100").rstrip("/")
providers = ProviderService()

app = FastAPI(
    title="NetSentinel Plus",
    version="1.0.0",
    description="Additive analyst console for metadata-only enrichment.",
)


@app.get("/api/addon/health")
async def addon_health() -> dict[str, Any]:
    backend = await asyncio.to_thread(_backend_get, "/api/health")
    return {
        "status": "online",
        "sidecar": "netsentinel_plus",
        "backend": backend,
        "providers": providers.status(),
        "existing_application_untouched": True,
    }


@app.get("/api/addon/status")
async def addon_status() -> dict[str, Any]:
    return {"providers": providers.status(), "backend_url": BACKEND_URL, "existing_application_untouched": True}


@app.get("/api/addon/live")
async def addon_live() -> dict[str, Any]:
    paths = {
        "health": "/api/health",
        "alerts": "/api/alerts?limit=20",
        "temporal": "/api/forensics/temporal",
        "launch_report": "/api/launch/report",
    }
    values = await asyncio.gather(*(asyncio.to_thread(_backend_get, path) for path in paths.values()), return_exceptions=True)
    return {name: _proxy_value(value) for name, value in zip(paths, values)}


@app.get("/api/addon/lookup")
async def addon_lookup(
    ip: str | None = Query(default=None, max_length=64),
    domain: str | None = Query(default=None, max_length=253),
    sha256: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    if not any((ip, domain, sha256)):
        raise HTTPException(status_code=400, detail="Provide ip, domain, or sha256")
    return await asyncio.to_thread(providers.lookup, ip=ip, domain=domain, sha256=sha256)


@app.get("/api/addon/assessment")
async def addon_assessment() -> dict[str, Any]:
    paths = {
        "health": "/api/health",
        "alerts": "/api/alerts?limit=100",
        "temporal": "/api/forensics/temporal",
        "launch_report": "/api/launch/report",
    }
    values = await asyncio.gather(*(asyncio.to_thread(_backend_get, path) for path in paths.values()), return_exceptions=True)
    live = {name: _proxy_value(value) for name, value in zip(paths, values)}
    alert_payload = live.get("alerts") or {}
    alert_items = alert_payload.get("alerts") if isinstance(alert_payload, dict) else []
    assessment = build_temporal_assessment(
        telemetry=live.get("temporal"),
        alerts=alert_items if isinstance(alert_items, list) else [],
        health=live.get("health"),
        launch_report=live.get("launch_report"),
    )
    return {"assessment": assessment, "source": "existing_backend_metadata", "score_unchanged": True}


@app.get("/api/addon/alert/{alert_id}/enrich")
async def enrich_existing_alert(alert_id: str) -> dict[str, Any]:
    alert = await asyncio.to_thread(_backend_get, f"/api/alerts/{_safe_path_value(alert_id)}")
    if isinstance(alert, dict) and alert.get("error"):
        raise HTTPException(status_code=502, detail=alert["error"])
    intelligence = await asyncio.to_thread(providers.enrich_alert, alert)
    return {"alert_id": alert_id, "intelligence": intelligence, "score_unchanged": True}


@app.get("/api/addon/alert/{alert_id}/brief")
async def brief_existing_alert(alert_id: str) -> dict[str, Any]:
    alert = await asyncio.to_thread(_backend_get, f"/api/alerts/{_safe_path_value(alert_id)}")
    if isinstance(alert, dict) and alert.get("error"):
        raise HTTPException(status_code=502, detail=alert["error"])
    intelligence = await asyncio.to_thread(providers.enrich_alert, alert)
    report = await asyncio.to_thread(providers.brief, alert, intelligence)
    return {"alert_id": alert_id, "intelligence": intelligence, "report": report, "score_unchanged": True}


@app.get("/", include_in_schema=False)
async def console() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


def _backend_get(path: str) -> dict[str, Any]:
    url = f"{BACKEND_URL}{path}"
    try:
        with urlopen(Request(url, headers={"User-Agent": "NetSentinel-Plus/1.0"}), timeout=4.0) as response:
            payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
            return payload if isinstance(payload, dict) else {"value": payload}
    except HTTPError as exc:
        return {"error": f"Existing backend returned HTTP {exc.code}"}
    except URLError:
        return {"error": "Existing NetSentinel backend is offline"}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"error": str(exc)[:240]}


def _proxy_value(value: Any) -> Any:
    return value if isinstance(value, dict) else {"error": str(value)[:240]}


def _safe_path_value(value: str) -> str:
    if not value or len(value) > 128 or any(character in value for character in ("/", "\\", "?", "#")):
        raise HTTPException(status_code=400, detail="Invalid alert identifier")
    return value
