import { Radar, ShieldCheck, Target } from "lucide-react";
import type { Alert, TemporalSummary } from "../types/alert";

export default function PortScanEvidencePanel({ alerts, temporal }: { alerts: Alert[]; temporal: TemporalSummary | null }) {
  const latest = alerts.find((alert) => alert.threatType === "Port Scan") ?? null;
  const features = temporal?.temporal_features;
  const ports = temporal?.top_ports?.slice(0, 6) ?? [];

  return (
    <section className="panel-base overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--bg-border)] px-5 py-4">
        <div className="flex items-center gap-2.5"><Radar size={16} className="text-cyan-300" /><div><p className="label-mono">Reconnaissance workbench</p><h2 className="mt-1 text-base font-semibold">Port-scan evidence and scoped review</h2></div></div>
        <span className="label-mono rounded-full border border-[var(--bg-border)] px-2.5 py-1">MITRE T1046 � metadata-only</span>
      </div>
      <div className="grid gap-3 p-5 md:grid-cols-3">
        <Signal icon={<Target size={15} />} label="Destination-port fan-out" value={`${features?.unique_destination_ports ?? 0}`} detail="unique ports in rolling window" />
        <Signal icon={<Radar size={15} />} label="SYN / ACK shape" value={metric(features?.syn_ack_ratio)} detail="one-sided probe signal" />
        <Signal icon={<ShieldCheck size={15} />} label="Latest assessment" value={latest?.threatType ?? "No active scan"} detail={latest ? `${latest.confidence.toFixed(1)}% � ${latest.severity}` : "Continue bounded observation"} />
      </div>
      <div className="grid gap-4 border-t border-[var(--bg-border)] px-5 py-4 lg:grid-cols-[1.2fr_1fr]">
        <div><p className="label-mono text-[8px]">Observed service targets</p><div className="mt-2 flex flex-wrap gap-1.5">{ports.length ? ports.map((port) => <span key={port.value} className="rounded-md border border-[var(--bg-border)] px-2 py-1 mono text-[10px] text-[var(--text-muted)]">{port.value} � {port.count}</span>) : <span className="mono text-[10px] text-[var(--text-dim)]">Awaiting flow metadata</span>}</div></div>
        <div><p className="label-mono text-[8px]">Analyst action</p><p className="mt-2 text-xs leading-5 text-[var(--text-muted)]">{latest?.responseAction ?? "Validate the source against approved scanner inventory, maintenance windows, and asset ownership. Review only the scanning source or segment; NetSentinel does not block traffic."}</p></div>
      </div>
    </section>
  );
}

function Signal({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: string; detail: string }) {
  return <div className="panel-inset p-4"><div className="flex items-center gap-2 text-[var(--text-muted)]">{icon}<span className="label-mono text-[8px]">{label}</span></div><div className="mono mt-4 text-xl font-semibold tabular-nums">{value}</div><p className="mt-1 text-[10px] text-[var(--text-dim)]">{detail}</p></div>;
}

function metric(value: number | undefined) {
  return value == null || !Number.isFinite(value) ? "�" : value.toFixed(3);
}