import { Activity, Clock3, Database, Network, RadioTower } from "lucide-react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ReactNode } from "react";
import type { TemporalSummary } from "../types/alert";

export default function TemporalForensicsPanel({ summary }: { summary: TemporalSummary | null }) {
  const features = summary?.temporal_features;
  const timeline = summary?.timeline ?? [];
  const protocols = Object.entries(summary?.protocols ?? {}).slice(0, 4);
  const ports = summary?.top_ports?.slice(0, 5) ?? [];

  return (
    <section className="panel-base overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--bg-border)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <Activity size={16} className="text-cyan-300" />
          <div>
            <p className="label-mono">Temporal forensics</p>
            <h2 className="mt-1 text-base font-semibold">Sequence evidence, not a single-flow guess</h2>
          </div>
        </div>
        <span className="label-mono rounded-full border border-[var(--bg-border)] px-2.5 py-1">{summary?.window_seconds ?? 300}s rolling · bounded</span>
      </div>

      <div className="grid gap-5 p-5 lg:grid-cols-[1.45fr_1fr]">
        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="label-mono">Flow volume by time bucket</span>
            <span className="mono text-[10px] text-[var(--text-dim)]">{summary?.events_in_window ?? 0} events</span>
          </div>
          <div className="h-[170px] rounded-xl border border-[var(--bg-border)] bg-[var(--bg-inset)] px-2 py-3">
            {timeline.length === 0 ? (
              <div className="flex h-full items-center justify-center label-mono text-[9px] text-[var(--text-dim)]">Awaiting telemetry window…</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id="temporalFlowFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#67e8f9" stopOpacity={0.42} />
                      <stop offset="100%" stopColor="#67e8f9" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="bucket" hide />
                  <YAxis hide allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: "#0d1728", border: "1px solid rgba(179,202,230,.2)", borderRadius: 8, fontSize: 11 }}
                    formatter={(value) => [`${Number(value).toLocaleString()} events`, "bucket"] as [string, string]}
                    labelFormatter={(value) => `Window bucket ${value}`}
                  />
                  <Area type="monotone" dataKey="events" stroke="#67e8f9" strokeWidth={2} fill="url(#temporalFlowFill)" isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-2">
          <ForensicMetric icon={<Clock3 size={13} />} label="IAT CV" value={formatMetric(features?.inter_arrival_cv)} detail="periodicity" />
          <ForensicMetric icon={<Network size={13} />} label="Port fan-out" value={`${features?.unique_destination_ports ?? 0}`} detail="unique ports" />
          <ForensicMetric icon={<RadioTower size={13} />} label="Burst ratio" value={formatMetric(features?.burst_ratio)} detail="peak / mean" />
          <ForensicMetric icon={<Database size={13} />} label="Out / in" value={formatMetric(features?.outbound_inbound_ratio)} detail="byte asymmetry" />
        </div>
      </div>

      <div className="grid gap-4 border-t border-[var(--bg-border)] px-5 py-4 sm:grid-cols-3">
        <SignalList title="Entropy" values={[`Sources ${formatMetric(features?.source_entropy_bits)} bits`, `Destinations ${formatMetric(features?.destination_entropy_bits)} bits`, `SYN/ACK ${formatMetric(features?.syn_ack_ratio)}`]} />
        <SignalList title="Top ports" values={ports.length ? ports.map((port) => `${port.value} · ${port.count}`) : ["No ports observed"]} />
        <SignalList title="Protocols" values={protocols.length ? protocols.map(([protocol, count]) => `${protocol} · ${count}`) : ["No protocol data"]} />
      </div>
    </section>
  );
}

function ForensicMetric({ icon, label, value, detail }: { icon: ReactNode; label: string; value: string; detail: string }) {
  return <div className="bento-box p-3"><div className="flex items-center gap-1.5 text-[var(--text-muted)]">{icon}<span className="label-mono text-[8px]">{label}</span></div><div className="mono mt-3 text-lg tabular-nums">{value}</div><div className="mt-1 text-[10px] text-[var(--text-dim)]">{detail}</div></div>;
}

function SignalList({ title, values }: { title: string; values: string[] }) {
  return <div><p className="label-mono text-[8px]">{title}</p><div className="mt-2 flex flex-wrap gap-1.5">{values.map((value) => <span key={value} className="rounded-md border border-[var(--bg-border)] px-2 py-1 mono text-[10px] text-[var(--text-muted)]">{value}</span>)}</div></div>;
}

function formatMetric(value: number | undefined) {
  return value == null || !Number.isFinite(value) ? "—" : value.toFixed(3);
}
