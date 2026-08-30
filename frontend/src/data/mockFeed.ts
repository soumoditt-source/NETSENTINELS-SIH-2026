import type { Alert, ModelStat, MitreCell, Severity, ThreatType } from "../types/alert";

// Preview model cards start unmeasured. The live feed hydrates the
// real-data XGBoost result from GET /api/training when available.
export const MODELS: ModelStat[] = [
  { name: "CIC-IDS2017 XGBoost", short: "CIC XGB", accuracy: null, latency: null, metricLabel: "not measured", active: false, threshold: 0.1, lastConfidence: null },
  { name: "DGA CNN-BiLSTM", short: "DGA", accuracy: null, latency: null, metricLabel: "not measured", active: false, threshold: 85, lastConfidence: null },
  { name: "C2 BiLSTM+FFT", short: "C2", accuracy: null, latency: null, metricLabel: "not measured", active: false, threshold: 90, lastConfidence: null },
  { name: "ETT Transformer", short: "ETT", accuracy: null, latency: null, metricLabel: "not measured", active: false, threshold: 75, lastConfidence: null },
];

// Full MITRE ATT&CK tactic columns (enterprise), a handful mapped to
// techniques NetSentinel actually emits (alert_manager static map).
export const MITRE_TACTICS: { tactic: string; technique: string; id: string }[] = [
  { tactic: "Reconnaissance", technique: "Active Scanning", id: "T1595" },
  { tactic: "Initial Access", technique: "Exploit Public App", id: "T1190" },
  { tactic: "Execution", technique: "Command & Scripting", id: "T1059" },
  { tactic: "Persistence", technique: "Scheduled Task", id: "T1053" },
  { tactic: "Defense Evasion", technique: "Obfuscated Files", id: "T1027" },
  { tactic: "Discovery", technique: "Network Service Disc.", id: "T1046" },
  { tactic: "Command & Control", technique: "App Layer Protocol", id: "T1071" },
  { tactic: "Command & Control", technique: "Dynamic Resolution", id: "T1568" },
  { tactic: "Command & Control", technique: "Encrypted Channel", id: "T1573" },
  { tactic: "Exfiltration", technique: "Exfil Over C2", id: "T1041" },
  { tactic: "Impact", technique: "Network DoS", id: "T1498" },
  { tactic: "Impact", technique: "Endpoint DoS", id: "T1499" },
];

export function emptyMitre(): MitreCell[] {
  return MITRE_TACTICS.map((m) => ({ ...m, hits: 0 }));
}

const INTERNAL = ["10.0.0.14", "10.0.0.22", "10.0.1.7", "192.168.1.40", "10.0.0.9"];
const EXTERNAL = ["198.51.100.24", "198.51.100.48", "203.0.113.19", "203.0.113.72", "192.0.2.210"];
const DGA_DOMAINS = ["xkqw8f3m.invalid", "vb7zp2qk.invalid", "m9x4tzw.invalid", "q1k8fjxn.invalid"];

let seq = 0;
const id = () => `al-${Date.now()}-${seq++}`;
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const jit = (base: number, spread: number) => +(base + (Math.random() - 0.5) * spread).toFixed(1);

// A scripted event on the 60s demo timeline (README §"Demo Script").
export interface ScriptEvent {
  atMs: number;
  make: () => Alert;
}

function benign(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Benign",
    severity: "info",
    sourceIP: pick(INTERNAL),
    destIP: pick(["198.51.100.14", "203.0.113.42", "192.0.2.140"]),
    confidence: jit(62, 20),
    model: "ETT Transformer",
    indicators: ["Nominal flow rate", "Bidirectional handshake complete"],
  };
}

function ddos(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "DDoS",
    severity: "critical",
    sourceIP: pick(EXTERNAL),
    destIP: "10.0.0.14",
    confidence: jit(99.5, 0.6),
    mitreTechnique: "Network DoS",
    mitreTactic: "Impact",
    model: "CIC-IDS2017 XGBoost",
    indicators: [
      "SYN flood — 61.2K pps",
      "Packet size variance ≈ 0",
      "Handshake completion 0.4%",
      "Fwd/bwd ratio 240:1",
    ],
  };
}

function c2(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "C2 Beacon",
    severity: "high",
    sourceIP: "10.0.0.22",
    destIP: pick(EXTERNAL),
    confidence: jit(94, 3),
    mitreTechnique: "App Layer Protocol",
    mitreTactic: "Command & Control",
    model: "C2 BiLSTM+FFT",
    beaconInterval: jit(58.3, 1.4),
    indicators: [
      "Dominant FFT freq 0.0172 Hz",
      "Beacon interval 58.3s ± 5%",
      "Spectral entropy 0.19",
      "Neris botnet signature",
    ],
  };
}

function dga(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "DGA",
    severity: "high",
    sourceIP: "10.0.1.7",
    domain: pick(DGA_DOMAINS),
    confidence: jit(93, 3),
    mitreTechnique: "Dynamic Resolution",
    mitreTactic: "Command & Control",
    model: "DGA CNN-BiLSTM",
    indicators: [
      "Shannon entropy 4.2",
      "Bigram score 0.02 (non-English)",
      "Consonant ratio 0.81",
      "Cryptolocker family",
    ],
  };
}

function portScan(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Port Scan",
    severity: "medium",
    sourceIP: pick(EXTERNAL),
    destIP: pick(INTERNAL),
    confidence: jit(87, 5),
    mitreTechnique: "Network Service Disc.",
    mitreTactic: "Discovery",
    model: "CIC-IDS2017 XGBoost",
    indicators: ["Vertical scan — 64 ports / 8s", "1 src → 64 dst ports", "No completed sessions"],
  };
}

function encrypted(): Alert {
  return {
    id: id(),
    timestamp: Date.now(),
    threatType: "Encrypted",
    severity: "medium",
    sourceIP: pick(INTERNAL),
    destIP: pick(EXTERNAL),
    confidence: jit(84, 6),
    mitreTechnique: "Encrypted Channel",
    mitreTactic: "Command & Control",
    model: "ETT Transformer",
    indicators: ["VPN tunnel fingerprint", "Large outbound / minimal inbound", "Possible exfiltration"],
  };
}

// The looping 60-second demo timeline.
export const DEMO_SCRIPT: ScriptEvent[] = [
  { atMs: 12_000, make: ddos },
  { atMs: 22_000, make: c2 },
  { atMs: 32_000, make: dga },
  { atMs: 44_000, make: encrypted },
  { atMs: 52_000, make: portScan },
];

export const PHASES: { atMs: number; label: string }[] = [
  { atMs: 0, label: "Baseline monitoring" },
  { atMs: 12_000, label: "Volumetric DDoS — SYN flood" },
  { atMs: 22_000, label: "C2 beacon correlation" },
  { atMs: 32_000, label: "DGA domain resolution" },
  { atMs: 44_000, label: "Encrypted tunnel analysis" },
  { atMs: 52_000, label: "Port scan fan-out" },
];

export function phaseFor(ms: number): string {
  let label = PHASES[0].label;
  for (const p of PHASES) if (ms >= p.atMs) label = p.label;
  return label;
}

export function makeBenign() {
  return benign();
}

// Base packets/sec envelope over the loop, spiking during DDoS.
export function basePps(ms: number): number {
  const s = ms / 1000;
  let pps = 900 + Math.sin(s / 3) * 180 + Math.random() * 120;
  if (s >= 12 && s < 20) pps += 42_000 * Math.min(1, (s - 12) / 1.5); // DDoS spike
  if (s >= 52 && s < 56) pps += 2_400;
  return Math.round(pps);
}

export const THREAT_TO_TACTIC: Record<ThreatType, string> = {
  DDoS: "Impact",
  "C2 Beacon": "Command & Control",
  DGA: "Command & Control",
  Encrypted: "Command & Control",
  "Port Scan": "Discovery",
  Benign: "",
};

export const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
