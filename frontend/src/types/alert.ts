// Normalized to netsentinel/pipeline/alert_manager.py output.
// This is the single contract shared by the mock feed and, later,
// the real ws://localhost:8100/ws stream.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ThreatType =
  | "DDoS"
  | "C2 Beacon"
  | "DGA"
  | "Encrypted"
  | "CIC behavioral anomaly"
  | "Port Scan"
  | "Benign";

export type ModelName =
  | "DDoS XGBoost"
  | "DGA CNN-BiLSTM"
  | "C2 BiLSTM+FFT"
  | "ETT Transformer"
  | "CIC-IDS2017 XGBoost";

export interface Alert {
  id: string;
  timestamp: number; // epoch ms
  threatType: ThreatType;
  severity: Severity;
  sourceIP: string;
  destIP?: string;
  domain?: string;
  confidence: number; // 0–100
  mitreTechnique?: string; // e.g. "T1498"
  mitreTactic?: string; // e.g. "Impact"
  model: ModelName;
  indicators: string[];
  beaconInterval?: number; // seconds, C2 only
  responseScope?: string;
  responseAction?: string;
  sourceCoords?: [number, number]; // [lat, lng] for 3D graph
  destCoords?: [number, number]; // [lat, lng] for 3D graph
}

export interface PacketSample {
  t: number; // epoch ms
  pps: number; // packets / sec
  critical: number;
  high: number;
  medium: number;
}

export interface ModelStat {
  name: ModelName;
  short: string;
  accuracy: number | null; // % when measured locally
  latency: number | null; // ms when measured locally
  metricLabel: string; // "F1" | "Accuracy"
  active: boolean;
  threshold: number; // decision threshold (%)
  lastConfidence: number | null; // most recent alert confidence
}

export interface TrainingSummary {
  status: "measured_real_data" | "not_available" | "unavailable";
  modelName?: string;
  testF1?: number;
  testRocAuc?: number;
  threshold?: number;
  algorithm?: string;
  modelVersion?: string;
  featureCount?: number;
  splitMethod?: string;
  trainingRunId?: string;
  rowCounts?: Record<string, number>;
  labelDistribution?: Record<string, number>;
  limitations: string[];
}

export interface TemporalSummary {
  window_seconds: number;
  events_in_window: number;
  total_events_observed: number;
  first_event_at: number | null;
  last_event_at: number | null;
  flows_per_second: number;
  packets_per_second: number;
  bytes_per_second: number;
  unique_sources: number;
  unique_destinations: number;
  protocols: Record<string, number>;
  event_types: Record<string, number>;
  top_ports?: Array<{ value: number; count: number }>;
  alerts_in_window: number;
  alert_classes: Record<string, number>;
  timeline?: Array<{ bucket: number; events: number; packets: number; bytes: number }>;
  temporal_features?: {
    inter_arrival_mean_seconds: number;
    inter_arrival_cv: number;
    source_entropy_bits: number;
    destination_entropy_bits: number;
    unique_destination_ports: number;
    syn_ack_ratio: number;
    outbound_inbound_ratio: number;
    burst_ratio: number;
  };
  metadata_only: boolean;
  read_only: boolean;
}

export interface MitreCell {
  tactic: string;
  technique: string;
  id: string;
  hits: number;
}

export interface FeedState {
  alerts: Alert[];
  packetRate: PacketSample[];
  threatCounts: Record<Severity, number>;
  models: ModelStat[];
  mitre: MitreCell[];
  totalFlows: number;
  flowsPerSec: number;
  phase: string;
  status: "monitoring" | "critical" | "connecting" | "offline";
  source: "mock" | "live" | "offline";
  training: TrainingSummary | null;
  temporal: TemporalSummary | null;
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
