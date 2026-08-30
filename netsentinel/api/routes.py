"""REST API Routes — Health, alerts, stats, simulation, PCAP, capture, graph."""
import os
import asyncio
import json
import time
import uuid
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse

from netsentinel.config import PCAP_UPLOAD_DIR, CAPTURE_INTERFACE
from netsentinel.coverage import get_coverage
from netsentinel.ingest.flow_adapter import iter_analyzer_events

MAX_PCAP_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_METADATA_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_METADATA_RECORDS = 20_000
METADATA_UPLOAD_DIR = Path(PCAP_UPLOAD_DIR).resolve() / "metadata"
METADATA_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
_SAFE_FIXTURE_CANDIDATES = [
    Path(__file__).resolve().parents[2] / "data" / "processed" / "safe_lab" / "netsentinel_attack_test_bundle_42",
    Path(__file__).resolve().parents[2] / "test_data" / "netsentinel_attack_test_bundle_42",
]
SAFE_FIXTURE_DIR = next(
    (candidate for candidate in _SAFE_FIXTURE_CANDIDATES if (candidate / "attack_signatures_42.manifest.json").is_file()),
    _SAFE_FIXTURE_CANDIDATES[-1],
)
LAUNCH_REPORT_PATH = Path(__file__).resolve().parents[2] / "reports" / "launch" / "launch_report.json"

router = APIRouter(prefix="/api")

# Module-level references to shared state (set in create_routes)
_packet_processor = None
_analyzer_ref     = None
_ws_hub_ref       = None
_sim_ctrl_ref     = None
_metadata_jobs: dict[str, dict] = {}
_pcap_jobs: dict[str, dict] = {}

# Throughput tracker (global, shared)
_start_time = time.time()


def create_routes(analyzer, alert_manager, ws_hub, simulator_control, packet_processor=None):
    """
    Create API routes with access to shared state.

    Args:
        analyzer:           FlowAnalyzer instance
        alert_manager:      AlertManager instance
        ws_hub:             WebSocketHub instance
        simulator_control:  dict with 'mode' and 'running' keys
        packet_processor:   PacketProcessor instance (optional)
    """
    global _packet_processor, _analyzer_ref, _ws_hub_ref, _sim_ctrl_ref
    _packet_processor = packet_processor
    _analyzer_ref     = analyzer
    _ws_hub_ref       = ws_hub
    _sim_ctrl_ref     = simulator_control

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    @router.get("/health")
    async def health():
        """System health — all components, read-only mode confirmation."""
        result = {
            "status": "online",
            "read_only_mode": True,
            "payload_decrypted": False,
            "uptime_s": round(time.time() - _start_time, 1),
            "models": analyzer.registry.get_status(),
            "pipeline": analyzer.get_stats(),
            "websocket_clients": ws_hub.client_count,
        }
        if _packet_processor:
            result["extractor"] = _packet_processor.stats
        return result

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    @router.get("/alerts")
    async def get_alerts(limit: int = 50, threat_class: str = ""):
        """Get recent alerts. Optionally filter by threat_class."""
        alerts = alert_manager.get_recent(limit)
        if threat_class:
            alerts = [a for a in alerts if threat_class.lower() in
                      str(a.get("threat_class", "")).lower()]
        return {
            "alerts":   alerts,
            "total":    alert_manager.total_count,
            "filtered": len(alerts),
        }

    @router.get("/alerts/{alert_id}")
    async def get_alert_detail(alert_id: str):
        """Get full detail of a specific alert including evidence chain."""
        alert = alert_manager.get_by_id(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert

    @router.get("/flows/{flow_id}")
    async def get_flow(flow_id: str):
        """Return alert evidence associated with a known flow identifier."""

        if len(flow_id) > 128 or any(character in flow_id for character in ("/", "\\")):
            raise HTTPException(status_code=400, detail="Invalid flow identifier")
        matches = [
            alert for alert in alert_manager.alerts
            if alert.get("flow_id") == flow_id or flow_id in alert.get("related_flow_ids", [])
        ]
        return {"flow_id": flow_id, "alerts": matches, "found": bool(matches)}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    @router.get("/stats")
    async def get_stats():
        """Get pipeline statistics including throughput and state size."""
        stats = analyzer.get_stats()
        stats["uptime_s"] = round(time.time() - _start_time, 1)
        if _packet_processor:
            stats["extractor"] = _packet_processor.stats
        return stats

    @router.get("/metrics")
    async def get_metrics():
        """Get evaluation metrics from the current replay session."""
        return _get_evaluation_metrics()

    # ------------------------------------------------------------------
    # Models / Detectors
    # ------------------------------------------------------------------
    @router.get("/models")
    async def list_models():
        """List all loaded ML models and rule detectors with their status."""
        return analyzer.registry.get_status()

    @router.get("/training")
    async def get_training_summary():
        """Return measured metadata for the repository-controlled real-data artifact."""
        return _get_training_summary()

    @router.get("/coverage")
    async def get_threat_coverage():
        """Return the bounded network-threat coverage contract and limitations."""
        return get_coverage()

    @router.get("/launch/report")
    async def get_launch_report():
        """Return the latest additive launch audit for the dashboard telemetry panel."""
        if not LAUNCH_REPORT_PATH.is_file():
            return {
                "status": "not_run",
                "message": "Run launch_netsentinel.bat or python tools/launch_demo.py first.",
            }
        try:
            return json.loads(LAUNCH_REPORT_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"Launch report unavailable: {exc}") from exc

    @router.get("/forensics/temporal")
    async def get_temporal_forensics():
        """Return bounded sliding-window metadata aggregates for the dashboard."""
        return analyzer.temporal_forensics.summary()

    @router.get("/forensics/jobs/{job_id}")
    async def get_forensics_job(job_id: str):
        """Return status for a metadata-only evidence replay job."""
        job = _metadata_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Evidence job not found")
        return job

    @router.get("/forensics/fixtures")
    async def get_safe_fixture_manifest():
        """Describe the repository-local safe metadata test bundle."""
        manifest_path = SAFE_FIXTURE_DIR / "attack_signatures_42.manifest.json"
        if not manifest_path.is_file():
            return {
                "status": "not_generated",
                "message": "Run tools/safe_lab/build_attack_test_bundle.py first.",
            }
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"Fixture manifest unavailable: {exc}") from exc

    @router.get("/forensics/fixtures/{file_format}")
    async def download_safe_fixture(file_format: str):
        """Download one generated safe metadata fixture format."""
        names = {
            "jsonl": "attack_signatures_42.jsonl",
            "csv": "attack_signatures_42.csv",
            "parquet": "attack_signatures_42.parquet",
            "manifest": "attack_signatures_42.manifest.json",
            "readme": "README.md",
        }
        filename = names.get(file_format.lower())
        if filename is None:
            raise HTTPException(status_code=404, detail="Supported fixture formats: jsonl, csv, parquet, manifest, readme")
        path = (SAFE_FIXTURE_DIR / filename).resolve()
        if path.parent != SAFE_FIXTURE_DIR.resolve() or not path.is_file():
            raise HTTPException(status_code=404, detail="Fixture is not generated")
        return FileResponse(path, filename=filename)

    # ------------------------------------------------------------------
    # Evidence graph
    # ------------------------------------------------------------------
    @router.get("/graph")
    async def get_evidence_graph():
        """
        Return the live correlation evidence graph.
        Nodes: sources, detectors, threat classes.
        Edges: triggered_by, correlated_with.
        """
        if not (analyzer.registry.correlation):
            return {"nodes": [], "edges": [], "note": "Correlation engine not loaded"}
        graph = analyzer.registry.correlation.get_evidence_graph()
        composites = analyzer.registry.correlation.get_all_composites()
        graph["composite_alerts"] = composites
        return graph

    # ------------------------------------------------------------------
    # Replay / Simulation
    # ------------------------------------------------------------------
    @router.post("/replay/start")
    async def start_replay(scenario: str = "mixed"):
        """
        Trigger a named safe scenario replay.
        All traffic is synthetic — no real packets are transmitted.

        Valid scenarios:
          normal | ddos | dga | c2 | port_scan | exfiltration | mixed
          syn_flood | udp_flood | horizontal_scan | vertical_scan
          slow_scan | beaconing | dns_tunnel | legit_service_c2
          mixed_enterprise
        """
        valid = {
            "normal", "ddos", "dga", "c2", "port_scan", "exfiltration", "mixed",
            "syn_flood", "udp_flood", "horizontal_scan", "vertical_scan",
            "slow_scan", "beaconing", "dns_tunnel", "legit_service_c2",
            "mixed_enterprise",
        }
        if scenario not in valid:
            return {"error": f"Invalid scenario. Valid: {sorted(valid)}"}
        simulator_control["mode"] = "mixed" if scenario == "mixed_enterprise" else scenario
        simulator_control["running"] = True
        return {
            "status": f"Replay started: {scenario}",
            "scenario": scenario,
            "read_only": True,
            "note": "All events are synthetic metadata — no real packets transmitted.",
        }

    @router.post("/replay/stop")
    async def stop_replay():
        simulator_control["running"] = False
        simulator_control["mode"]    = "normal"
        return {"status": "Replay stopped"}

    @router.post("/replay/reset")
    async def reset_replay():
        simulator_control["running"] = False
        simulator_control["mode"]    = "normal"
        analyzer.flows_processed = 0
        alert_manager.reset()
        return {"status": "Replay reset — stats and alerts cleared"}

    @router.get("/replay/scenarios")
    async def list_replay_scenarios():
        """Return the safe red-team cases available to the live dashboard."""
        return {
            "metadata_only": True,
            "read_only": True,
            "execution": "offline synthetic event generation",
            "scenarios": [
                {"id": "mixed_enterprise", "label": "Mixed enterprise", "coverage": "benign + multi-stage anomalies"},
                {"id": "syn_flood", "label": "SYN flood-like", "coverage": "volumetric TCP metadata"},
                {"id": "udp_flood", "label": "UDP flood-like", "coverage": "volumetric UDP metadata"},
                {"id": "port_scan", "label": "Port scan-like", "coverage": "reconnaissance fan-out"},
                {"id": "beaconing", "label": "Periodic beacon-like", "coverage": "C2 timing metadata"},
                {"id": "dga", "label": "DGA-like DNS", "coverage": "DNS entropy and n-gram anomaly"},
                {"id": "dns_tunnel", "label": "DNS tunnel-like", "coverage": "long-label and TXT metadata"},
                {"id": "exfiltration", "label": "Asymmetric transfer-like", "coverage": "outbound/inbound imbalance"},
                {"id": "legit_service_c2", "label": "Legitimate-service C2-like", "coverage": "behavioral chain on approved cloud service"},
            ],
            "safety_note": "No packets, payloads, executables, malware, credentials, or callbacks are generated.",
        }

    # Legacy alias
    @router.post("/simulate/{attack_type}")
    async def start_simulation(attack_type: str):
        return await start_replay(attack_type)

    # ------------------------------------------------------------------
    # Evaluation (honest, with limitations)
    # ------------------------------------------------------------------
    @router.get("/evaluation")
    async def get_evaluation():
        """
        Returns reproducible metrics from the current replay session.

        Note: These metrics apply to the synthetic replay only.
        Production performance on real traffic may differ significantly.
        """
        return _get_evaluation_metrics()

    # ------------------------------------------------------------------
    # PCAP / Live Capture
    # ------------------------------------------------------------------
    @router.post("/pcap/upload")
    async def upload_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
        """Upload a PCAP file for offline read-only analysis."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
            return {"error": "Invalid file type. Upload .pcap or .pcapng"}

        safe_name = Path(file.filename or "").name
        if not safe_name or safe_name != file.filename or safe_name in {".", ".."}:
            raise HTTPException(status_code=400, detail="Unsafe filename")
        job_id = uuid.uuid4().hex
        save_path = os.path.join(PCAP_UPLOAD_DIR, f"{job_id}_{safe_name}")
        written = 0
        with open(save_path, "wb") as handle:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_PCAP_UPLOAD_BYTES:
                    handle.close()
                    os.remove(save_path)
                    raise HTTPException(status_code=413, detail="PCAP exceeds upload size limit")
                handle.write(chunk)

        _pcap_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "job_id": job_id,
            "filename": safe_name,
            "size_bytes": written,
            "read_only": True,
            "payload_decrypted": False,
        }
        background_tasks.add_task(_process_pcap_background, save_path, job_id, analyzer, ws_hub)
        return {
            "status": "PCAP uploaded — processing started",
            "filename": safe_name,
            "size_bytes": written,
            "read_only": True,
            "note": "No packets will be transmitted back to the source network.",
        }

    @router.get("/pcap/jobs/{job_id}")
    async def get_pcap_job(job_id: str):
        """Return bounded offline PCAP extraction status."""
        job = _pcap_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="PCAP job not found")
        return job

    @router.post("/forensics/upload")
    async def upload_metadata_evidence(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
        """Queue a bounded metadata-only JSONL, CSV, or Parquet replay.

        Pickle, executables, payloads, and decrypted content are deliberately
        unsupported. Uploaded files are removed after the replay completes.
        """
        original_name = Path(file.filename or "").name
        suffix = Path(original_name).suffix.lower()
        if not original_name or original_name != file.filename or suffix not in {".jsonl", ".ndjson", ".csv", ".parquet"}:
            raise HTTPException(status_code=400, detail="Use a metadata-only .jsonl, .ndjson, .csv, or .parquet file")

        job_id = uuid.uuid4().hex
        save_path = METADATA_UPLOAD_DIR / f"{job_id}{suffix}"
        written = 0
        try:
            with save_path.open("wb") as handle:
                while chunk := await file.read(1024 * 1024):
                    written += len(chunk)
                    if written > MAX_METADATA_UPLOAD_BYTES:
                        raise HTTPException(status_code=413, detail="Metadata evidence exceeds 25 MB limit")
                    handle.write(chunk)
        except Exception:
            save_path.unlink(missing_ok=True)
            raise

        _metadata_jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "filename": original_name,
            "size_bytes": written,
            "max_records": MAX_METADATA_RECORDS,
            "read_only": True,
            "payload_decrypted": False,
        }
        background_tasks.add_task(_process_metadata_upload, save_path, job_id, original_name, analyzer, ws_hub)
        return _metadata_jobs[job_id]

    @router.post("/capture/start")
    async def start_capture(interface: str = CAPTURE_INTERFACE):
        """Start live packet capture on the specified interface (read-only)."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        if _packet_processor._live_running:
            return {"error": "Live capture already running"}
        event_queue = asyncio.Queue(maxsize=10_000)
        await _packet_processor.start_live_capture(interface, event_queue)
        asyncio.create_task(_consume_live_events(event_queue, analyzer, ws_hub))
        return {"status": f"Live capture started on '{interface}'", "read_only": True}

    @router.post("/capture/stop")
    async def stop_capture():
        """Stop live packet capture."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        _packet_processor.stop_live_capture()
        return {"status": "Live capture stopped"}

    @router.get("/extractor/stats")
    async def extractor_stats():
        """Detailed extraction layer statistics."""
        if _packet_processor is None:
            return {"error": "Extraction layer not initialized"}
        return _packet_processor.stats

    # ------------------------------------------------------------------
    # Admin
    # ------------------------------------------------------------------
    @router.post("/reset")
    async def reset_stats():
        """Reset pipeline stats and alerts (for testing)."""
        analyzer.flows_processed = 0
        alert_manager.reset()
        return {"status": "reset"}

    return router


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_evaluation_metrics() -> dict:
    metrics_path = Path(__file__).resolve().parents[2] / "reports" / "evaluation" / "latest" / "metrics.json"
    if not metrics_path.is_file():
        return {
            "status": "not_run",
            "metrics": None,
            "note": "Run python -m netsentinel.evaluation.run_benchmark before presenting metrics.",
            "limitations": ["No benchmark result is available yet."],
        }
    try:
        result = json.loads(metrics_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "metrics": None, "note": str(exc)}
    return {
        "status": "measured_local_replay",
        "metrics": result,
        "source": str(metrics_path),
        "note": "These measurements apply only to the recorded local safe replay and are not production claims.",
    }


def _get_training_summary() -> dict:
    artifact_dir = Path(__file__).resolve().parents[2] / "data" / "artifacts" / "models" / "cicids2017_attack_xgboost" / "v1"
    metrics_path = artifact_dir / "metrics.json"
    manifest_path = artifact_dir / "training_manifest.json"
    if not metrics_path.is_file() or not manifest_path.is_file():
        return {
            "status": "not_available",
            "model_name": None,
            "metrics": None,
            "limitations": ["No repository-controlled real-data training artifact is available."],
        }
    try:
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "unavailable", "metrics": None, "limitations": [str(exc)]}
    return {
        "status": "measured_real_data",
        "model_name": manifest.get("model_name"),
        "model_version": manifest.get("model_version"),
        "algorithm": manifest.get("algorithm"),
        "feature_count": len(manifest.get("features", [])),
        "feature_order": manifest.get("features", []),
        "training_run_id": manifest.get("training_run_id"),
        "split_method": manifest.get("split_method"),
        "random_seed": manifest.get("random_seed"),
        "row_counts": manifest.get("row_counts", {}),
        "label_distribution": manifest.get("label_distribution", {}),
        "threshold": manifest.get("threshold"),
        "metrics": metrics,
        "limitations": manifest.get("limitations", []),
        "source_split_sha256": manifest.get("source_split_sha256", {}),
    }


# ── Background tasks ──────────────────────────────────────────────────────────

async def _process_pcap_background(pcap_path: str, job_id: str, analyzer, ws_hub):
    from netsentinel.extractor import PacketProcessor

    processor = PacketProcessor()
    alert_count = 0
    event_count = 0
    job = _pcap_jobs.get(job_id, {"job_id": job_id})
    job.update({"status": "running", "started_at": time.time()})
    try:
        for event in processor.process_pcap(pcap_path):
            event_count += 1
            alert = analyzer.analyze_flow(event)
            if alert:
                alert_count += 1
                await ws_hub.broadcast_alert(alert)
            if event_count % 100 == 0:
                await asyncio.sleep(0)
        job.update({
            "status": "completed",
            "events_processed": event_count,
            "alerts_generated": alert_count,
            "elapsed_ms": round((time.time() - job.get("started_at", time.time())) * 1000, 2),
        })
        await ws_hub.broadcast_stats({
            "pcap_complete": True,
            "pcap_file": os.path.basename(pcap_path),
            "events_processed": event_count,
            "alerts_generated": alert_count,
            **analyzer.get_stats(),
        })
    except Exception as exc:
        job.update({"status": "rejected", "events_processed": event_count, "alerts_generated": alert_count, "error": str(exc)})
    finally:
        Path(pcap_path).unlink(missing_ok=True)
        _pcap_jobs[job_id] = job


async def _process_metadata_upload(path: Path, job_id: str, original_name: str, analyzer, ws_hub):
    """Replay a user-provided metadata file with a hard record limit."""
    started = time.perf_counter()
    processed = 0
    alerts = 0
    result = _metadata_jobs.get(job_id, {})
    result.update({"status": "running", "started_at": time.time()})
    try:
        for event in iter_analyzer_events(path, max_records=MAX_METADATA_RECORDS):
            processed += 1
            alert = analyzer.analyze_flow(event)
            if alert:
                alerts += 1
                await ws_hub.broadcast_alert(alert)
            if processed % 250 == 0:
                await asyncio.sleep(0)
        elapsed = time.perf_counter() - started
        result.update({
            "status": "completed",
            "records_processed": processed,
            "alerts_generated": alerts,
            "elapsed_ms": round(elapsed * 1000, 2),
            "events_per_second": round(processed / max(elapsed, 1e-9), 2),
            "temporal_summary": analyzer.temporal_forensics.summary(),
        })
    except Exception as exc:
        result.update({
            "status": "rejected",
            "records_processed": processed,
            "alerts_generated": alerts,
            "error": str(exc),
        })
    finally:
        path.unlink(missing_ok=True)
        _metadata_jobs[job_id] = result
        await ws_hub.broadcast_stats({"metadata_upload": result, **analyzer.get_stats()})


async def _consume_live_events(event_queue: asyncio.Queue, analyzer, ws_hub):
    while True:
        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=5.0)
            alert = analyzer.analyze_flow(event)
            if alert:
                await ws_hub.broadcast_alert(alert)
        except asyncio.TimeoutError:
            continue
        except Exception:
            break
