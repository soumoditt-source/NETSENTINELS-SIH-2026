"""NetSentinel — Main FastAPI Application (SIH 26145).

Entry point. On startup it:
1. Loads optional ONNX models, the trusted local XGBoost artifact, and rule detectors
2. Initializes the extraction layer (PCAP / Zeek → NormalizedEvent)
3. Wires a StreamingStateManager into the FlowAnalyzer
4. Starts a background traffic-simulation loop
5. Serves WebSocket for real-time alerts to the React dashboard
6. Provides REST endpoints for health, alerts, stats, PCAP upload, live capture

Read-only mode is enforced: READ_ONLY_MODE=True, NO_DECRYPTION_MODE=True.
"""
import asyncio
import os
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from netsentinel.models.registry import ModelRegistry
from netsentinel.pipeline.analyzer import FlowAnalyzer
from netsentinel.pipeline.alert_manager import AlertManager
from netsentinel.api.websocket import WebSocketHub
from netsentinel.api.routes import create_routes, router
from netsentinel.simulator.traffic_gen import generate_event
from netsentinel.extractor import PacketProcessor
from netsentinel.config import (
    MAX_ALERTS_STORED, FLOW_IDLE_TIMEOUT, FLOW_ACTIVE_TIMEOUT, SESSION_MIN_FLOWS,
)

# ============================================================
# Initialize Components
# ============================================================
app = FastAPI(
    title="NetSentinel",
    description="AI-Powered Network Threat Detection Pipeline",
    version="1.0.0",
)

# CORS — allow React dashboard (any origin for dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared state
registry = ModelRegistry()
alert_manager = AlertManager(max_stored=MAX_ALERTS_STORED)
analyzer = FlowAnalyzer(registry, alert_manager)
ws_hub = WebSocketHub()
simulator_control = {"mode": "normal", "running": False, "rate": 10}
packet_processor = PacketProcessor(
    idle_timeout=FLOW_IDLE_TIMEOUT,
    active_timeout=FLOW_ACTIVE_TIMEOUT,
    session_min_flows=SESSION_MIN_FLOWS,
)
API_PORT = int(os.getenv("NETSENTINEL_PORT", "8100"))


# ============================================================
# Startup Event — Load Models
# ============================================================
@app.on_event("startup")
async def startup():
    print("=" * 60)
    print("  NetSentinel — SIH 26145 Threat Intelligence Platform")
    print("  'See Everything. Touch Nothing. Trust the Chain.'")
    print("  READ_ONLY_MODE=True  |  NO_DECRYPTION_MODE=True")
    print("=" * 60)

    # Load all ML models + deterministic detectors
    registry.load_all()

    # Create routes with shared state (including extraction layer)
    create_routes(analyzer, alert_manager, ws_hub, simulator_control, packet_processor)
    app.include_router(router)

    # Start background simulation loop
    asyncio.create_task(simulation_loop())

    print("\n[>] Server ready!")
    print(f"   REST API:      http://localhost:{API_PORT}/api/health")
    print(f"   WebSocket:     ws://localhost:{API_PORT}/ws")
    print(f"   Evaluation:    GET  http://localhost:{API_PORT}/api/evaluation")
    print(f"   PCAP Upload:   POST http://localhost:{API_PORT}/api/pcap/upload")
    print(f"   Live Capture:  POST http://localhost:{API_PORT}/api/capture/start")
    print(f"   Docs:          http://localhost:{API_PORT}/docs")


# ============================================================
# WebSocket Endpoint
# ============================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_hub.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for client messages
            data = await websocket.receive_text()
            # Client can send commands like {"action": "start_sim", "mode": "ddos"}
            try:
                import json
                msg = json.loads(data)
                if msg.get("action") == "start_sim":
                    simulator_control["mode"] = msg.get("mode", "mixed")
                    simulator_control["running"] = True
                elif msg.get("action") == "stop_sim":
                    simulator_control["running"] = False
                    simulator_control["mode"] = "normal"
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)


# ============================================================
# Background Simulation Loop
# ============================================================
async def simulation_loop():
    """
    Background task that continuously generates traffic events,
    runs them through the AI pipeline, and broadcasts alerts.
    """
    print("  [~] Simulation loop started (send POST /api/simulate/mixed to begin)")
    
    stats_interval = 2.0  # Send stats every 2 seconds
    last_stats_time = time.time()
    
    while True:
        if not simulator_control["running"]:
            await asyncio.sleep(0.5)
            continue
        
        mode = simulator_control["mode"]
        rate = simulator_control.get("rate", 10)
        
        try:
            # Generate event
            event = generate_event(mode)
            
            # Run through pipeline
            alert = analyzer.analyze_flow(event)
            
            # If threat detected, broadcast to dashboard
            if alert:
                await ws_hub.broadcast_alert(alert)
        except Exception as e:
            # Log but don't crash — one bad event shouldn't kill the loop
            pass
        
        # Periodically send stats update
        now = time.time()
        if now - last_stats_time >= stats_interval:
            stats = analyzer.get_stats()
            stats["simulation_mode"] = mode
            await ws_hub.broadcast_stats(stats)
            last_stats_time = now
        
        # Rate control
        await asyncio.sleep(1.0 / rate)
