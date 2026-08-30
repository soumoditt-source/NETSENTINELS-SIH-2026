import { ArrowRight, CheckCircle2, Eye, Info, Network, ShieldAlert, UploadCloud } from "lucide-react";
import { useState, type ChangeEvent, type ReactNode } from "react";
import type { Alert, FeedState } from "../types/alert";
import DataEvidencePanel from "./DataEvidencePanel";
import TemporalForensicsPanel from "./TemporalForensicsPanel";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8100";

interface Props {
  feed: FeedState;
  onInspect: (alert: Alert) => void;
}

export default function ExplainMode({ feed, onInspect }: Props) {
  const suspicious = feed.alerts.filter((alert) => alert.threatType !== "Benign");
  const latest = suspicious[0];
  const risk = feed.status === "critical" ? "High" : suspicious.length ? "Review" : "Low";
  const sourceLabel = feed.source === "live" ? "live telemetry" : feed.source === "mock" ? "scripted preview" : "offline - awaiting ingest";
  const healthLabel = feed.source === "live" ? "Connected" : feed.source === "mock" ? "Preview" : "Offline";
  const why = latest?.indicators[0] ?? "No unusual pattern has been raised in the current window.";
  const [uploadStatus, setUploadStatus] = useState("Ready for metadata-only evidence");
  const [pcapStatus, setPcapStatus] = useState("Ready for an authorized PCAP");

  async function uploadEvidence(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setUploadStatus(`Queueing ${file.name}…`);
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch(`${API_BASE}/api/forensics/upload`, { method: "POST", body });
      const job = await response.json();
      if (!response.ok) throw new Error(job.detail || "Upload rejected");
      setUploadStatus(`Job ${job.job_id.slice(0, 8)} queued · max ${job.max_records.toLocaleString()} records`);
      for (let attempt = 0; attempt < 20; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        const statusResponse = await fetch(`${API_BASE}/api/forensics/jobs/${job.job_id}`);
        const status = await statusResponse.json();
        if (status.status === "completed") {
          setUploadStatus(`${status.records_processed.toLocaleString()} records replayed · ${status.alerts_generated} alerts`);
          return;
        }
        if (status.status === "rejected") throw new Error(status.error || "Evidence rejected");
      }
      setUploadStatus("Replay continues in the background · inspect job status in API docs");
    } catch (error) {
      setUploadStatus(error instanceof Error ? error.message : "Evidence upload failed");
    }
  }

  async function uploadPcap(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setPcapStatus(`Queueing ${file.name} for offline extraction...`);
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch(`${API_BASE}/api/pcap/upload`, { method: "POST", body });
      const job = await response.json();
      if (!response.ok || job.error) throw new Error(job.detail || job.error || "PCAP rejected");
      setPcapStatus(`PCAP job ${job.job_id.slice(0, 8)} queued - headers only`);
      for (let attempt = 0; attempt < 40; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        const statusResponse = await fetch(`${API_BASE}/api/pcap/jobs/${job.job_id}`);
        const status = await statusResponse.json();
        if (status.status === "completed") {
          setPcapStatus(`${status.events_processed.toLocaleString()} metadata flows extracted - ${status.alerts_generated} alerts`);
          return;
        }
        if (status.status === "rejected") throw new Error(status.error || "PCAP extraction failed");
      }
      setPcapStatus("Extraction continues in the background - inspect the PCAP job API");
    } catch (error) {
      setPcapStatus(error instanceof Error ? error.message : "PCAP upload failed");
    }
  }

  return (
    <div className="grid gap-5">
      <section className="glass-card p-6 lg:p-8">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div className="max-w-3xl">
            <p className="label-mono mb-3">Explain mode · {sourceLabel}</p>
            <h2 className="text-2xl font-semibold tracking-tight lg:text-4xl">Cyber early warning without touching the network</h2>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-[var(--text-muted)]">
              We observe one-way network traffic, find unusual patterns, explain why they matter, and recommend what a security team should verify next.
            </p>
          </div>
          <div className="panel-inset min-w-[220px] p-4">
            <div className="flex items-center gap-2 text-sm font-medium"><CheckCircle2 size={16} className="text-[var(--sev-low)]" /> Read-only monitoring</div>
            <p className="mt-2 text-xs leading-5 text-[var(--text-muted)]">No blocking, return traffic, or encrypted payload decryption.</p>
          </div>
        </div>
      </section>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <SituationCard icon={<Eye size={17} />} label="Traffic observed" value={`${feed.totalFlows.toLocaleString()} flows`} detail={`${feed.flowsPerSec.toFixed(1)} flows per second`} />
        <SituationCard icon={<ShieldAlert size={17} />} label="Suspicious cases" value={`${suspicious.length}`} detail="Prioritized for review" />
        <SituationCard icon={<Info size={17} />} label="Current risk" value={risk} detail="Confidence is not proof" />
        <SituationCard icon={<CheckCircle2 size={17} />} label="System health" value={healthLabel} detail="Input source is visible" />
        <SituationCard icon={<ArrowRight size={17} />} label="Next check" value={latest ? "Inspect evidence" : "Keep observing"} detail={latest ? "Open the latest case" : "No action sent to network"} />
      </div>

      <section className="panel-base p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="label-mono">Why this matters</p>
            <h3 className="mt-1 text-lg font-semibold">Human-readable evidence, not a verdict</h3>
          </div>
          <span className="label-mono rounded border border-[var(--bg-border)] px-2 py-1">{latest ? `${latest.confidence.toFixed(1)}% · ${latest.severity}` : "No active case"}</span>
        </div>
        <p className="mt-4 max-w-3xl text-sm leading-6 text-[var(--text-muted)]">{latest ? `${latest.sourceIP} showed ${why.toLowerCase()}. This can be unusual in context, but metadata alone does not prove malicious activity.` : "NetSentinel is watching for fan-out, timing, DNS, encrypted-session, and transfer patterns."}</p>
        {latest && (
          <button className="btn-premium mt-5" onClick={() => onInspect(latest)}>Open evidence <ArrowRight size={15} /></button>
        )}
      </section>

      {feed.training?.status === "measured_real_data" && (
        <section className="panel-inset p-4 text-xs leading-5 text-[var(--text-muted)]">
          <div className="label-mono mb-2">Measured model evidence</div>
          <p>
            {feed.training.algorithm ?? "XGBoost"} · {feed.training.modelVersion ?? "version recorded in artifact"} · {feed.training.featureCount ?? "—"} features · capture-held-out evaluation on real CIC-IDS2017 flow records.
            Test F1: <strong className="text-[var(--text-main)]">{feed.training.testF1 == null ? "—" : `${(feed.training.testF1 * 100).toFixed(1)}%`}</strong>
            {feed.training.testRocAuc == null ? "" : ` · ROC-AUC ${(feed.training.testRocAuc * 100).toFixed(1)}%`}. These are dataset-specific, not universal accuracy claims.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(feed.training.rowCounts ?? {}).map(([split, count]) => <span key={split} className="rounded border border-[var(--bg-border)] px-2 py-1">{split}: {count.toLocaleString()}</span>)}
            {Object.entries(feed.training.labelDistribution ?? {}).slice(0, 6).map(([label, count]) => <span key={label} className="rounded border border-[var(--bg-border)] px-2 py-1">{label}: {count.toLocaleString()}</span>)}
          </div>
        </section>
      )}

      <TemporalForensicsPanel summary={feed.temporal} />
      <DataEvidencePanel training={feed.training} />
      <section className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
        <div className="panel-base p-5">
          <div className="flex items-center gap-2"><UploadCloud size={16} className="text-[var(--text-muted)]" /><div><p className="label-mono">Evidence replay</p><h3 className="mt-1 text-lg font-semibold">Drop a safe trace</h3></div></div>
          <p className="mt-3 text-xs leading-5 text-[var(--text-muted)]">JSONL, CSV, or Parquet metadata only · 25 MB · 20,000 records. Pickle, executables, payloads, and decrypted content are rejected.</p>
          <label className="btn-ghost mt-4 cursor-pointer"><UploadCloud size={15} /> Choose evidence file<input className="sr-only" type="file" accept=".jsonl,.ndjson,.csv,.parquet" onChange={uploadEvidence} /></label>
          <p className="mt-3 text-[11px] text-[var(--text-dim)]">{uploadStatus}</p>
        </div>
        <div className="panel-base p-5">
          <div className="flex items-center gap-2"><Network size={16} className="text-[var(--text-muted)]" /><div><p className="label-mono">Actual network evidence</p><h3 className="mt-1 text-lg font-semibold">Drop an authorized PCAP</h3></div></div>
          <p className="mt-3 text-xs leading-5 text-[var(--text-muted)]">Offline `.pcap`, `.pcapng`, or `.cap` only. NetSentinel extracts headers, flow timing, DNS, TLS/QUIC metadata, and sizes; it does not execute files or decrypt payloads.</p>
          <label className="btn-ghost mt-4 cursor-pointer"><UploadCloud size={15} /> Choose PCAP<input className="sr-only" type="file" accept=".pcap,.pcapng,.cap" onChange={uploadPcap} /></label>
          <p className="mt-3 text-[11px] text-[var(--text-dim)]">{pcapStatus}</p>
        </div>
      </section>

      <section className="panel-inset p-4 text-xs leading-5 text-[var(--text-muted)]">
        <strong className="text-[var(--text-main)]">Important limitation: </strong>
        legitimate services, scheduled updates, backups, approved scanners, and monitoring agents can look unusual. Verify with approved endpoint and change-management telemetry.
      </section>
    </div>
  );
}

function SituationCard({ icon, label, value, detail }: { icon: ReactNode; label: string; value: string; detail: string }) {
  return (
    <div className="bento-box p-4">
      <div className="flex items-center gap-2 text-[var(--text-muted)]">{icon}<span className="label-mono text-[8px]">{label}</span></div>
      <div className="mt-4 text-lg font-semibold">{value}</div>
      <div className="mt-1 text-[11px] text-[var(--text-dim)]">{detail}</div>
    </div>
  );
}
