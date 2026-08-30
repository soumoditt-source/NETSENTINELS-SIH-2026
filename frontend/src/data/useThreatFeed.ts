import { useEffect, useRef, useState } from "react";
import type { Alert, FeedState, PacketSample, Severity, TemporalSummary, TrainingSummary } from "../types/alert";
import {
  DEMO_SCRIPT,
  MODELS,
  THREAT_TO_TACTIC,
  basePps,
  emptyMitre,
  makeBenign,
  phaseFor,
} from "./mockFeed";

/**
 * ── Live backend switch ───────────────────────────────────────────────
 * Set to your NetSentinel WebSocket to consume real alerts:
 *   const WS_URL = "ws://localhost:8100/ws";
 *
 * The dashboard is live-only by default. Set VITE_ENABLE_MOCK_FEED=true for
 * an explicitly labelled scripted preview; judge launches never silently
 * replace missing telemetry with invented data.
 * ──────────────────────────────────────────────────────────────────────
 */
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8100";
const WS_URL = `${API_BASE.replace(/^http/, "ws")}/ws`;
const MOCK_ENABLED = import.meta.env.VITE_ENABLE_MOCK_FEED === "true";

const LOOP_MS = 60_000;
const TICK_MS = 900;
const MAX_ALERTS = 50;
const MAX_SAMPLES = 60;

const zeroCounts = (): Record<Severity, number> => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

function initialState(): FeedState {
  return {
    alerts: [],
    packetRate: [],
    threatCounts: zeroCounts(),
    models: MODELS.map((m) => ({ ...m })),
    mitre: emptyMitre(),
    totalFlows: 0,
    flowsPerSec: 0,
    phase: "Awaiting backend ingest",
    status: "offline",
    source: "offline",
    training: null,
    temporal: null,
  };
}

/**
 * Transform backend alert schema → frontend Alert interface.
 * 
 * Backend schema (from alert_manager.py):
 *   - timestamp: ISO 8601 string
 *   - confidence: float 0-1
 *   - severity: UPPERCASE
 *   - threat_class: snake_case
 *   - mitre: nested object
 *   - evidence: dict
 *   - geo: nested object
 * 
 * Frontend schema (types/alert.ts):
 *   - timestamp: epoch ms
 *   - confidence: 0-100 percentage
 *   - severity: lowercase
 *   - threatType: camelCase
 *   - mitreTechnique/mitreTactic: flat
 *   - indicators: string array
 *   - sourceCoords/destCoords: [lat, lng] tuples
 */
function parseBackendAlert(raw: any): Alert {
  const evidence = raw.evidence ?? raw.feature_snapshot ?? {};
  const supportingEvidence = Array.isArray(raw.supporting_evidence)
    ? raw.supporting_evidence.filter((item: unknown): item is string => typeof item === "string")
    : [];
  const beaconMatch = supportingEvidence.join(" ").match(/mean\s+([\d.]+)s/i);
  const beaconInterval = typeof evidence.beacon_interval === "number"
    ? evidence.beacon_interval
    : beaconMatch ? Number(beaconMatch[1]) : undefined;
  // Transform evidence dict → human-readable indicators array
  const indicators: string[] = [...supportingEvidence.slice(0, 4)];
  if (indicators.length === 0) {
    if (evidence.pps) indicators.push(`${evidence.pps.toLocaleString()} pps`);
    if (evidence.flow_packets_per_second) indicators.push(`${Math.round(evidence.flow_packets_per_second).toLocaleString()} packets/s`);
    if (evidence.avg_pkt_size) indicators.push(`Avg packet size: ${evidence.avg_pkt_size} bytes`);
    if (evidence.syn_ack_ratio !== undefined) indicators.push(`SYN/ACK ratio: ${Number(evidence.syn_ack_ratio).toFixed(2)}`);
    if (beaconInterval) indicators.push(`Beacon interval: ${beaconInterval.toFixed(1)}s`);
    if (evidence.entropy) indicators.push(`Entropy: ${Number(evidence.entropy).toFixed(2)}`);
  }

  // Fallback indicators if evidence is empty
  if (indicators.length === 0) {
    indicators.push(`Detected by ${raw.model_name || "ML model"}`);
  }

  return {
    id: raw.id,
    timestamp: new Date(raw.timestamp).getTime(), // ISO → epoch ms
    threatType: raw.threat_class as Alert["threatType"],
    severity: raw.severity.toLowerCase() as Severity,
    sourceIP: raw.source_ip,
    destIP: raw.dest_ip,
    domain: evidence.domain ?? raw.flow_meta?.domain,
    confidence: Math.round(raw.confidence * 1000) / 10, // 0.9937 → 99.4
    mitreTechnique: raw.mitre?.technique,
    mitreTactic: raw.mitre?.tactic,
    model: raw.model_name as Alert["model"],
    indicators,
    beaconInterval,
    responseScope: raw.containment_scope?.scope_type,
    responseAction: raw.containment_scope?.recommended_action,
    // Transform geo object → coordinate tuples for 3D graph
    sourceCoords: raw.geo?.src_lat && raw.geo?.src_lon 
      ? [raw.geo.src_lat, raw.geo.src_lon] 
      : undefined,
    destCoords: raw.geo?.dst_lat && raw.geo?.dst_lon 
      ? [raw.geo.dst_lat, raw.geo.dst_lon] 
      : undefined,
  };
}

// Fold a single alert into feed state. Shared by mock + live paths so
// downstream aggregation is identical regardless of source.
function ingest(prev: FeedState, alert: Alert, source: FeedState["source"]): FeedState {
  const alerts = [alert, ...prev.alerts].slice(0, MAX_ALERTS);
  const threatCounts = { ...zeroCounts() };
  for (const a of alerts) threatCounts[a.severity] += 1;

  const models = prev.models.map((m) =>
    m.name === alert.model
      ? { ...m, active: true, lastConfidence: alert.confidence }
      : { ...m, active: false },
  );

  const mitre = prev.mitre.map((c) => ({ ...c }));
  const tactic = THREAT_TO_TACTIC[alert.threatType];
  if (tactic && alert.mitreTechnique) {
    const cell =
      mitre.find((c) => c.tactic === tactic && c.technique.startsWith(alert.mitreTechnique!.slice(0, 4))) ??
      mitre.find((c) => c.tactic === tactic);
    if (cell) cell.hits += 1;
  }

  const status: FeedState["status"] =
    alert.severity === "critical" ? "critical" : prev.status === "critical" ? "critical" : "monitoring";

  return { ...prev, alerts, threatCounts, models, mitre, status, source };
}

export function useThreatFeed(): FeedState {
  const [state, setState] = useState<FeedState>(initialState);
  const start = useRef(Date.now());
  const firedRef = useRef<Set<number>>(new Set());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let mockIv: ReturnType<typeof setInterval> | null = null;
    let sampleIv: ReturnType<typeof setInterval> | null = null;
    let fallbackTimer: ReturnType<typeof setTimeout> | null = null;
    let live = false;

    fetch(`${API_BASE}/api/training`)
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("training endpoint unavailable")))
      .then((summary: TrainingSummary & {
        model_name?: string;
        model_version?: string;
        feature_count?: number;
        split_method?: string;
        training_run_id?: string;
        row_counts?: Record<string, number>;
        label_distribution?: TrainingSummary["labelDistribution"];
        metrics?: { test?: { f1?: number; roc_auc?: number } };
      }) => {
        setState((prev) => ({
          ...prev,
          training: {
            ...summary,
            modelName: summary.model_name ?? summary.modelName,
            modelVersion: summary.model_version,
            featureCount: summary.feature_count,
            splitMethod: summary.split_method,
            trainingRunId: summary.training_run_id,
            rowCounts: summary.row_counts ?? summary.rowCounts,
            labelDistribution: summary.label_distribution ?? summary.labelDistribution,
            testF1: summary.metrics?.test?.f1,
            testRocAuc: summary.metrics?.test?.roc_auc,
          },
          models: prev.models.map((model) => model.name === "CIC-IDS2017 XGBoost"
            ? {
                ...model,
                accuracy: summary.metrics?.test?.f1 == null ? null : +(summary.metrics.test.f1 * 100).toFixed(1),
                metricLabel: summary.metrics?.test?.f1 == null ? "not measured" : "held-out test F1",
                threshold: summary.threshold == null ? model.threshold : +(summary.threshold * 100).toFixed(2),
              }
            : model),
        }));
      })
      .catch(() => undefined);

    fetch(`${API_BASE}/api/forensics/temporal`)
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("temporal endpoint unavailable")))
      .then((summary: TemporalSummary) => setState((prev) => ({ ...prev, temporal: summary })))
      .catch(() => undefined);

    // Chart samples run in BOTH modes so the packet-rate plot always moves.
    const startSampling = (isLive: boolean) => {
      sampleIv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - start.current) % LOOP_MS;
        setState((prev) => {
          const recent = prev.alerts.filter((a) => now - a.timestamp < 3000);
          const sample: PacketSample = {
            t: now,
            pps: isLive ? (prev.temporal?.packets_per_second ?? 0) : basePps(elapsed),
            critical: recent.filter((a) => a.severity === "critical").length,
            high: recent.filter((a) => a.severity === "high").length,
            medium: recent.filter((a) => a.severity === "medium").length,
          };
          const packetRate = [...prev.packetRate, sample].slice(-MAX_SAMPLES);
          const flowsPerSec = isLive
            ? (prev.temporal?.flows_per_second ?? 0)
            : +(40 + Math.random() * 6).toFixed(1);
          return {
            ...prev,
            packetRate,
            totalFlows: isLive
              ? (prev.temporal?.total_events_observed ?? prev.totalFlows)
              : prev.totalFlows + Math.round(flowsPerSec * (TICK_MS / 1000)),
            flowsPerSec,
            phase: isLive ? "Live capture" : phaseFor(elapsed),
          };
        });
      }, TICK_MS);
    };

    const startMock = () => {
      if (live || mockIv) return;
      setState((prev) => ({ ...prev, source: "mock" }));
      startSampling(false);
      mockIv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - start.current) % LOOP_MS;
        const loopIndex = Math.floor((now - start.current) / LOOP_MS);
        const phase = phaseFor(elapsed);
        const fired = firedRef.current;

        DEMO_SCRIPT.forEach((ev, i) => {
          const key = loopIndex * 100 + i;
          if (elapsed >= ev.atMs && elapsed < ev.atMs + TICK_MS && !fired.has(key)) {
            fired.add(key);
            setState((prev) => ({ ...ingest(prev, ev.make(), "mock"), phase }));
          }
        });
        if (fired.size > 400) firedRef.current = new Set();
        if (Math.random() < 0.5) {
          setState((prev) => ({ ...ingest(prev, makeBenign(), "mock"), phase }));
        }
      }, TICK_MS);
    };

    const markUnavailable = () => {
      if (MOCK_ENABLED) {
        startMock();
        return;
      }
      setState((prev) => ({
        ...prev,
        source: "offline",
        status: "offline",
        flowsPerSec: 0,
        phase: "Awaiting backend ingest",
      }));
    };

    if (WS_URL) {
      setState((prev) => ({ ...prev, status: "connecting" }));
      try {
        ws = new WebSocket(WS_URL);
        fallbackTimer = setTimeout(() => {
          if (!live) markUnavailable();
        }, 4000);
        ws.onopen = () => {
          live = true;
          if (fallbackTimer) clearTimeout(fallbackTimer);
          if (mockIv) {
            clearInterval(mockIv);
            mockIv = null;
          }
          if (sampleIv) {
            clearInterval(sampleIv);
            sampleIv = null;
          }
          setState((prev) => ({ ...prev, source: "live", status: "monitoring" }));
          startSampling(true);
        };
        ws.onmessage = (e) => {
          try {
            const rawAlert = JSON.parse(e.data);
            if (rawAlert.type === "stats") {
              const stats = rawAlert.data ?? {};
              const temporal = stats.temporal_forensics ?? stats.metadata_upload?.temporal_summary;
              setState((prev) => ({
                ...prev,
                temporal: temporal ?? prev.temporal,
                totalFlows: stats.flows_processed ?? temporal?.total_events_observed ?? prev.totalFlows,
                flowsPerSec: temporal?.flows_per_second ?? prev.flowsPerSec,
              }));
              return;
            }
            // Handle backend message format: {"type": "alert", "data": {...}}
            const alertData = rawAlert.type === "alert" && rawAlert.data ? rawAlert.data : rawAlert;
            const alert = parseBackendAlert(alertData);
            setState((prev) => ingest(prev, alert, "live"));
          } catch (err) {
            console.warn("[WebSocket] Failed to parse alert:", err);
            /* ignore malformed frames */
          }
        };
        ws.onerror = () => {
          if (!live) markUnavailable();
        };
        ws.onclose = () => {
          if (!live) markUnavailable();
        };
      } catch {
        markUnavailable();
      }
    } else {
      markUnavailable();
    }

    return () => {
      ws?.close();
      if (mockIv) clearInterval(mockIv);
      if (sampleIv) clearInterval(sampleIv);
      if (fallbackTimer) clearTimeout(fallbackTimer);
    };
  }, []);

  return state;
}
