import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Activity, BadgeCheck, Eye, LockKeyhole } from "lucide-react";
import ShieldCube from "./ShieldCube";
import type { FeedState } from "../types/alert";

interface Props {
  status: FeedState["status"];
  flowsPerSec: number;
  totalFlows: number;
  phase: string;
  source: FeedState["source"];
  mode: "explain" | "soc";
  onModeChange: (mode: "explain" | "soc") => void;
}

export default function Header({ status, flowsPerSec, totalFlows, phase, source, mode, onModeChange }: Props) {
  const [clock, setClock] = useState("");
  useEffect(() => {
    const timer = setInterval(() => setClock(new Date().toLocaleTimeString("en-GB", { hour12: false })), 1000);
    return () => clearInterval(timer);
  }, []);

  const critical = status === "critical";
  const unavailable = status === "offline";
  const connecting = status === "connecting";
  const dotColor = critical ? "var(--sev-critical)" : unavailable || connecting ? "var(--sev-medium)" : "var(--sev-low)";
  const statusLabel = critical ? "Threat active" : unavailable ? "Awaiting ingest" : connecting ? "Connecting" : "Monitoring";
  const sourceLabel = source === "live" ? "live" : source === "mock" ? "preview" : "offline";
  const sourceTitle = source === "live"
    ? "Connected to backend WebSocket"
    : source === "mock"
      ? "Explicit preview mode; not production evidence"
      : "Backend WebSocket unavailable; no fabricated telemetry is shown";

  return (
    <header className="flex items-center justify-between gap-6 border-b border-[var(--bg-border)] px-6 py-4">
      <div className="flex items-center gap-3">
        <ShieldCube />
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[15px] font-semibold tracking-tight">NetSentinel</h1>
            <span className="label-mono text-[8px] text-cyan-300">SIH 26145</span>
            <span className="label-mono rounded border border-[var(--bg-border)] px-1.5 py-0.5 text-[9px]">NIDS</span>
            <span
              className="label-mono rounded border px-1.5 py-0.5 text-[8px]"
              style={{
                color: source === "live" ? "var(--sev-low)" : source === "mock" ? "var(--text-dim)" : "var(--sev-medium)",
                borderColor: source === "live" ? "var(--sev-low)" : source === "mock" ? "var(--bg-border)" : "var(--sev-medium)",
              }}
              title={sourceTitle}
            >
              {sourceLabel}
            </span>
          </div>
          <p className="label-mono mt-0.5 text-[9.5px] normal-case tracking-[0.04em] text-[var(--text-dim)]">{phase} - unidirectional IP traffic intelligence</p>
        </div>
      </div>

      <div className="hidden items-center gap-2 xl:flex" aria-label="NetSentinel trust guarantees">
        <TrustBadge icon={<Eye size={12} />} label="READ-ONLY" title="No command or traffic is sent back into the monitored network." />
        <TrustBadge icon={<LockKeyhole size={12} />} label="METADATA-ONLY" title="Encrypted payloads are never decrypted." />
        <TrustBadge icon={<BadgeCheck size={12} />} label="EXPLAINABLE" title="Every alert includes evidence, limitations, and a recommended verification." />
      </div>

      <div className="flex items-center gap-5">
        <div className="hidden items-center gap-1 rounded-lg border border-[var(--bg-border)] p-1 sm:flex">
          <button aria-pressed={mode === "explain"} className={`btn-ghost px-2.5 py-1.5 text-[10px] ${mode === "explain" ? "is-active" : ""}`} onClick={() => onModeChange("explain")}>Explain</button>
          <button aria-pressed={mode === "soc"} className={`btn-ghost px-2.5 py-1.5 text-[10px] ${mode === "soc" ? "is-active" : ""}`} onClick={() => onModeChange("soc")}>SOC analyst</button>
        </div>
        <Metric label="Flows / sec" value={flowsPerSec.toFixed(1)} />
        <div className="hidden h-8 w-px bg-[var(--bg-border)] md:block" />
        <Metric label="Total flows" value={totalFlows.toLocaleString()} />
        <div className="hidden h-8 w-px bg-[var(--bg-border)] lg:block" />
        <div className="hidden items-center gap-1.5 mono text-[13px] text-[var(--text-muted)] lg:flex"><Activity size={13} className="text-[var(--text-dim)]" />{clock}</div>
        <div className="flex items-center gap-2 pl-1">
          <span className="pulse-dot inline-block h-2 w-2 rounded-full" style={{ background: dotColor, color: dotColor }} />
          <span className="label-mono text-[10px]" style={{ color: critical ? "var(--sev-critical)" : "var(--text-main)" }}>{statusLabel}</span>
        </div>
      </div>
    </header>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="text-right"><div className="mono text-[15px] font-semibold leading-none">{value}</div><div className="label-mono mt-1 text-[9px]">{label}</div></div>;
}

function TrustBadge({ icon, label, title }: { icon: ReactNode; label: string; title: string }) {
  return <span title={title} className="trust-badge">{icon}{label}</span>;
}
