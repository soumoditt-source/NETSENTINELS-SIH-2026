import { BookOpen, CircleAlert, Eye, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8100";
type CoverageStatus = "active" | "partial" | "out_of_scope";

type CoverageItem = {
  family: string;
  name: string;
  status: CoverageStatus;
  techniques: string[];
  detectors: string[];
  observed_signals: string[];
  limitation: string;
  test_scenarios: string[];
};

type CoverageResponse = {
  as_of?: string;
  framework?: string;
  scope?: string;
  taxonomy_note?: string;
  counts?: Record<CoverageStatus, number>;
  items?: CoverageItem[];
};

export default function ThreatCoveragePanel() {
  const [coverage, setCoverage] = useState<CoverageResponse | null>(null);
  const [filter, setFilter] = useState<"all" | CoverageStatus>("all");

  useEffect(() => {
    let mounted = true;
    fetch(`${API_BASE}/api/coverage`)
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("coverage unavailable")))
      .then((next: CoverageResponse) => { if (mounted) setCoverage(next); })
      .catch(() => undefined);
    return () => { mounted = false; };
  }, []);

  const items = useMemo(() => {
    const all = coverage?.items ?? [];
    return filter === "all" ? all : all.filter((item) => item.status === filter);
  }, [coverage, filter]);
  const counts = coverage?.counts ?? { active: 0, partial: 0, out_of_scope: 0 };

  return (
    <section className="panel-base overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--bg-border)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <BookOpen size={16} className="text-cyan-300" />
          <div>
            <p className="label-mono">Threat coverage contract</p>
            <h2 className="mt-1 text-base font-semibold">What the one-way sensor can actually recognize</h2>
          </div>
        </div>
        <span className="label-mono rounded-full border border-[var(--bg-border)] px-2.5 py-1">as of {coverage?.as_of ?? "—"}</span>
      </div>

      <div className="grid gap-3 p-5 md:grid-cols-4">
        <CoverageSummary icon={<Eye size={14} />} label="Active path" value={counts.active} tone="text-[var(--sev-low)]" onClick={() => setFilter("active")} />
        <CoverageSummary icon={<CircleAlert size={14} />} label="Partial / corroborate" value={counts.partial} tone="text-[var(--sev-medium)]" onClick={() => setFilter("partial")} />
        <CoverageSummary icon={<ShieldCheck size={14} />} label="Endpoint-only" value={counts.out_of_scope} tone="text-[var(--sev-high)]" onClick={() => setFilter("out_of_scope")} />
        <div className="bento-box p-3">
          <p className="label-mono text-[8px]">Observation boundary</p>
          <p className="mt-2 text-[11px] leading-4 text-[var(--text-muted)]">{coverage?.scope ?? "Loading passive metadata scope..."}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 border-t border-[var(--bg-border)] px-5 py-3">
        {(["all", "active", "partial", "out_of_scope"] as const).map((value) => (
          <button key={value} className={filter === value ? "btn-premium !px-2.5 !py-1.5 !text-[9px]" : "btn-ghost !px-2.5 !py-1.5 !text-[9px]"} onClick={() => setFilter(value)}>
            {value === "all" ? "All families" : value === "out_of_scope" ? "Endpoint-only" : value === "active" ? "Active" : "Partial"}
          </button>
        ))}
        <span className="ml-auto label-mono self-center text-[8px]">{items.length} mapped families</span>
      </div>

      <div className="grid max-h-[510px] gap-2 overflow-y-auto px-5 pb-5">
        {items.map((item) => <CoverageRow key={`${item.family}-${item.name}`} item={item} />)}
      </div>
      <p className="border-t border-[var(--bg-border)] px-5 py-3 text-[10px] leading-4 text-[var(--text-dim)]">{coverage?.taxonomy_note ?? "Coverage is loading..."}</p>
    </section>
  );
}

function CoverageSummary({ icon, label, value, tone, onClick }: { icon: ReactNode; label: string; value: number; tone: string; onClick: () => void }) {
  return <button className="bento-box p-3 text-left transition hover:border-cyan-300/40" onClick={onClick}><div className={`flex items-center gap-1.5 ${tone}`}>{icon}<span className="label-mono text-[8px] text-[var(--text-muted)]">{label}</span></div><strong className={`mono mt-3 block text-xl ${tone}`}>{value}</strong><span className="mt-1 block text-[10px] text-[var(--text-dim)]">view mapped families</span></button>;
}

function CoverageRow({ item }: { item: CoverageItem }) {
  const statusLabel = item.status === "out_of_scope" ? "endpoint-only" : item.status;
  const statusColor = item.status === "active" ? "text-[var(--sev-low)]" : item.status === "partial" ? "text-[var(--sev-medium)]" : "text-[var(--sev-high)]";
  return (
    <article className="rounded-xl border border-[var(--bg-border)] bg-[var(--bg-inset)] p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div><p className="label-mono text-[8px] text-cyan-300">{item.family}</p><h3 className="mt-1 text-xs font-semibold">{item.name}</h3></div>
        <span className={`label-mono rounded-full border border-[var(--bg-border)] px-2 py-1 ${statusColor}`}>{statusLabel}</span>
      </div>
      <div className="mt-3 grid gap-2 text-[10px] text-[var(--text-muted)] md:grid-cols-[.7fr_1.3fr_1.5fr]">
        <div><span className="label-mono text-[8px]">ATT&amp;CK</span><p className="mt-1 mono">{item.techniques.join(" · ") || "—"}</p></div>
        <div><span className="label-mono text-[8px]">Signals</span><p className="mt-1 leading-4">{item.observed_signals.join(" · ")}</p></div>
        <div><span className="label-mono text-[8px]">Limit</span><p className="mt-1 leading-4">{item.limitation}</p></div>
      </div>
    </article>
  );
}
