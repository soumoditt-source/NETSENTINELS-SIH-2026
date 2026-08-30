import { Database, Download, FileSearch, Play, RotateCcw, ShieldCheck, Square } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { TrainingSummary } from "../types/alert";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8100";
const SAFE_SCENARIOS = [
  ["mixed_enterprise", "Mixed enterprise"],
  ["syn_flood", "SYN flood-like"],
  ["udp_flood", "UDP flood-like"],
  ["port_scan", "Port scan-like"],
  ["beaconing", "Beacon-like timing"],
  ["dga", "DGA-like DNS"],
  ["dns_tunnel", "DNS tunnel-like"],
  ["exfiltration", "Asymmetric transfer-like"],
  ["legit_service_c2", "Legitimate-service C2-like"],
] as const;

export default function DataEvidencePanel({ training }: { training: TrainingSummary | null }) {
  const [replayStatus, setReplayStatus] = useState("Analysis is ready");
  const [replayBusy, setReplayBusy] = useState(false);
  const [scenario, setScenario] = useState("mixed_enterprise");
  const rows = training?.rowCounts ?? {};
  const totalRows = Object.values(rows).reduce((sum, count) => sum + count, 0);
  const labels = Object.entries(training?.labelDistribution ?? {}).slice(0, 4);

  async function launchAnalysis() {
    setReplayBusy(true);
    setReplayStatus("Launching controlled replay...");
    try {
      const response = await fetch(`${API_BASE}/api/replay/start?scenario=${encodeURIComponent(scenario)}`, { method: "POST" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || result.error || "Replay unavailable");
      setReplayStatus("Analysis active - metadata only");
    } catch (error) {
      setReplayStatus(error instanceof Error ? error.message : "Replay unavailable");
    } finally {
      setReplayBusy(false);
    }
  }

  async function stopAnalysis() {
    setReplayBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/replay/stop`, { method: "POST" });
      if (!response.ok) throw new Error("Unable to stop replay");
      setReplayStatus("Analysis paused - evidence remains available");
    } catch (error) {
      setReplayStatus(error instanceof Error ? error.message : "Unable to stop replay");
    } finally {
      setReplayBusy(false);
    }
  }

  async function resetAnalysis() {
    setReplayBusy(true);
    try {
      const response = await fetch(`${API_BASE}/api/replay/reset`, { method: "POST" });
      if (!response.ok) throw new Error("Unable to reset analysis");
      setReplayStatus("Analysis reset - ready for a clean run");
    } catch (error) {
      setReplayStatus(error instanceof Error ? error.message : "Unable to reset analysis");
    } finally {
      setReplayBusy(false);
    }
  }

  return (
    <section className="panel-base overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--bg-border)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <ShieldCheck size={16} className="text-cyan-300" />
          <div>
            <p className="label-mono">Evidence ledger</p>
            <h2 className="mt-1 text-base font-semibold">Two safe data lanes</h2>
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <span className="label-mono mr-1">provenance first</span>
          <select className="rounded border border-[var(--bg-border)] bg-[var(--bg-panel)] px-2.5 py-2 text-[10px] text-[var(--text-main)]" value={scenario} onChange={(event) => setScenario(event.target.value)} disabled={replayBusy} aria-label="Safe analysis scenario">
            {SAFE_SCENARIOS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <button className="btn-premium !px-3 !py-2 !text-[10px]" onClick={launchAnalysis} disabled={replayBusy}>
            <Play size={13} /> {replayBusy ? "Working..." : "Launch analysis"}
          </button>
          <button className="btn-ghost !px-2.5 !py-2 !text-[10px]" onClick={stopAnalysis} disabled={replayBusy} title="Pause safe replay">
            <Square size={12} /> Stop
          </button>
          <button className="btn-ghost !px-2.5 !py-2 !text-[10px]" onClick={resetAnalysis} disabled={replayBusy} title="Clear alerts and temporal state">
            <RotateCcw size={12} /> Reset
          </button>
        </div>
      </div>
      <div className="grid gap-3 p-5 md:grid-cols-2">
        <DataLane
          icon={<Database size={16} />}
          label="Detection telemetry"
          title="CIC-IDS2017 flow records"
          tone="REAL BENCHMARK"
          detail={`${training?.featureCount ?? 78} engineered flow features · ${totalRows.toLocaleString()} prepared rows · capture-held-out evaluation`}
          footer={labels.map(([label, count]) => `${label} ${count.toLocaleString()}`).join(" · ") || "Awaiting local training manifest"}
        />
        <DataLane
          icon={<FileSearch size={16} />}
          label="Investigation replay"
          title="Safe metadata evidence"
          tone="CONTROLLED LAB"
          detail="JSONL / CSV / Parquet traces with explicit ground truth, checksums, and bounded replay"
          footer="No breach dump · no PII · no executable payload"
          action={
            <div className="mt-3 flex flex-wrap gap-2">
              <a className="btn-ghost !px-2.5 !py-1.5 !text-[10px]" href={`${API_BASE}/api/forensics/fixtures/jsonl`} download><Download size={12} /> JSONL</a>
              <a className="btn-ghost !px-2.5 !py-1.5 !text-[10px]" href={`${API_BASE}/api/forensics/fixtures/csv`} download><Download size={12} /> CSV</a>
              <a className="btn-ghost !px-2.5 !py-1.5 !text-[10px]" href={`${API_BASE}/api/forensics/fixtures/parquet`} download><Download size={12} /> Parquet</a>
            </div>
          }
          actionText={replayStatus}
        />
      </div>
    </section>
  );
}

function DataLane({ icon, label, title, tone, detail, footer, action, actionText }: { icon: ReactNode; label: string; title: string; tone: string; detail: string; footer: string; action?: ReactNode; actionText?: string }) {
  return (
    <div className="bento-box p-4">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-cyan-300">
          {icon}
          <span className="label-mono text-[8px] text-[var(--text-muted)]">{label}</span>
        </div>
        <span className="label-mono text-[8px] text-[var(--sev-low)]">{tone}</span>
      </div>
      <h3 className="mt-4 text-sm font-semibold">{title}</h3>
      <p className="mt-2 text-xs leading-5 text-[var(--text-muted)]">{detail}</p>
      <p className="mt-3 border-t border-[var(--bg-border)] pt-3 mono text-[10px] text-[var(--text-dim)]">{footer}</p>
      {action}
      {actionText && <p className="mt-2 text-[10px] text-[var(--text-dim)]">{actionText}</p>}
    </div>
  );
}
