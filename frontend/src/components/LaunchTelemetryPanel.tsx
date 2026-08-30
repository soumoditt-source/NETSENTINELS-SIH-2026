import { Activity, CheckCircle2, Gauge, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8100";

type BinaryMetrics = {
  rows?: number;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1?: number;
  roc_auc?: number | null;
};

type LaunchReport = {
  generated_at_utc?: string;
  real_data?: {
    status?: string;
    dataset?: string;
    splits?: Record<string, BinaryMetrics>;
  };
  safe_pipeline?: {
    events_replayed?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    latency_p95_ms?: number;
    false_positives?: number;
  };
  safety?: {
    read_only?: boolean;
    payload_decrypted?: boolean;
    malware_or_executable_testing?: boolean;
  };
};

const SPLIT_ORDER = ["train", "validation", "test"] as const;

export default function LaunchTelemetryPanel({ liveEvents = 0 }: { liveEvents?: number }) {
  const [report, setReport] = useState<LaunchReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/launch/report`);
        if (!response.ok) return;
        const next = (await response.json()) as LaunchReport;
        if (mounted) setReport(next);
      } finally {
        if (mounted) setLoading(false);
      }
    };
    void load();
    const interval = window.setInterval(() => void load(), 5000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const test = report?.real_data?.splits?.test;
  const safe = report?.safe_pipeline;
  const safeScore = safe ? `${percent(safe.f1)} F1` : "Awaiting audit";
  const generated = report?.generated_at_utc
    ? new Date(report.generated_at_utc).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "not run";

  return (
    <section className="panel-base overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--bg-border)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <Gauge size={16} className="text-cyan-300" />
          <div>
            <p className="label-mono">Launch telemetry</p>
            <h2 className="mt-1 text-base font-semibold">Binary 0/1 evidence, kept honest</h2>
          </div>
        </div>
        <span className="label-mono rounded-full border border-[var(--bg-border)] px-2.5 py-1">audit {generated}</span>
      </div>

      <div className="grid gap-3 p-5 md:grid-cols-3">
        <ScoreCard
          icon={<DatabaseIcon />}
          label="REAL HELD-OUT DATA"
          title={report?.real_data?.dataset ?? "CIC-IDS2017"}
          rows={test?.rows}
          values={[
            ["Accuracy", percent(test?.accuracy)],
            ["Precision", percent(test?.precision)],
            ["Recall", percent(test?.recall)],
            ["F1", percent(test?.f1)],
            ["ROC-AUC", percent(test?.roc_auc)],
          ]}
        />
        <ScoreCard
          icon={<Activity size={15} />}
          label="SAFE REAL-WORLD-LIKE REPLAY"
          title="Mixed enterprise telemetry"
          rows={safe?.events_replayed}
          values={[
            ["Precision", percent(safe?.precision)],
            ["Recall", percent(safe?.recall)],
            ["F1", percent(safe?.f1)],
            ["P95 latency", safe?.latency_p95_ms == null ? "—" : `${safe.latency_p95_ms.toFixed(2)} ms`],
            ["False positives", safe?.false_positives == null ? "—" : `${safe.false_positives}`],
          ]}
        />
        <div className="bento-box p-4">
          <div className="flex items-center gap-2 text-cyan-300"><ShieldCheck size={15} /><span className="label-mono text-[8px] text-[var(--text-muted)]">OPERATING GUARANTEE</span></div>
          <h3 className="mt-4 text-sm font-semibold">Read-only evidence lane</h3>
          <div className="mt-3 grid gap-2">
            <StatusRow label="Live window" value={`${liveEvents.toLocaleString()} events`} active />
            <StatusRow label="Payload decryption" value={report?.safety?.payload_decrypted ? "enabled" : "disabled"} active={!report?.safety?.payload_decrypted} />
            <StatusRow label="Automatic blocking" value="disabled" active />
            <StatusRow label="Safe suite" value={safeScore} active={Boolean(safe)} />
          </div>
        </div>
      </div>
      <section className="border-t border-[var(--bg-border)] px-5 py-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="label-mono">Complete measured scorecard</p>
            <h3 className="mt-1 text-sm font-semibold">Every prepared split, same binary 0/1 contract</h3>
          </div>
          <span className="text-[10px] text-[var(--text-dim)]">No score is rounded up to meet a target</span>
        </div>
        <div className="mt-4 grid gap-3 lg:grid-cols-3">
          {SPLIT_ORDER.map((split) => <SplitCard key={split} name={split} metrics={report?.real_data?.splits?.[split]} />)}
        </div>
      </section>
      <div className="flex items-center gap-2 border-t border-[var(--bg-border)] px-5 py-3 text-[10px] text-[var(--text-dim)]">
        <CheckCircle2 size={13} className="text-[var(--sev-low)]" />
        {loading ? "Reading the latest launch audit..." : "Scores are dataset/scenario-specific; they are not a universal malware-detection rate."}
        <RefreshCw size={12} className="ml-auto" />
      </div>
    </section>
  );
}

function SplitCard({ name, metrics }: { name: string; metrics?: BinaryMetrics }) {
  const values: [string, string][] = [
    ["Accuracy", percent(metrics?.accuracy)],
    ["Precision", percent(metrics?.precision)],
    ["Recall", percent(metrics?.recall)],
    ["F1", percent(metrics?.f1)],
    ["ROC-AUC", percent(metrics?.roc_auc)],
  ];
  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-base)]/40 p-3">
      <div className="flex items-center justify-between gap-3">
        <span className="label-mono text-[9px]">{name}</span>
        <span className="mono text-[10px] text-[var(--text-dim)]">{metrics?.rows == null ? "not measured" : `${metrics.rows.toLocaleString()} rows`}</span>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
        {values.map(([label, value]) => <div key={label} className="flex items-center justify-between gap-2 border-b border-[var(--bg-border)] pb-1"><span className="text-[10px] text-[var(--text-dim)]">{label}</span><strong className="mono text-[11px] tabular-nums">{value}</strong></div>)}
      </div>
    </div>
  );
}

function ScoreCard({ icon, label, title, rows, values }: { icon: ReactNode; label: string; title: string; rows?: number; values: [string, string][] }) {
  return (
    <div className="bento-box p-4">
      <div className="flex items-center gap-2 text-cyan-300">{icon}<span className="label-mono text-[8px] text-[var(--text-muted)]">{label}</span></div>
      <h3 className="mt-4 text-sm font-semibold">{title}</h3>
      <p className="mt-1 mono text-[10px] text-[var(--text-dim)]">{rows == null ? "No launch report" : `${rows.toLocaleString()} labelled rows/events`}</p>
      <div className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2">
        {values.map(([name, value]) => <div key={name} className="flex items-center justify-between gap-2 border-b border-[var(--bg-border)] pb-1"><span className="text-[10px] text-[var(--text-dim)]">{name}</span><strong className="mono text-[11px] tabular-nums">{value}</strong></div>)}
      </div>
    </div>
  );
}

function StatusRow({ label, value, active }: { label: string; value: string; active: boolean }) {
  return <div className="flex items-center justify-between gap-3 rounded-md border border-[var(--bg-border)] px-2.5 py-2"><span className="text-[10px] text-[var(--text-muted)]">{label}</span><span className={active ? "mono text-[10px] text-[var(--sev-low)]" : "mono text-[10px] text-[var(--sev-high)]"}>{value}</span></div>;
}

function DatabaseIcon() {
  return <span className="inline-flex h-4 w-4 items-center justify-center rounded border border-cyan-300/40 text-[9px]">DB</span>;
}

function percent(value?: number | null) {
  return value == null || !Number.isFinite(value) ? "—" : `${(value * 100).toFixed(1)}%`;
}
