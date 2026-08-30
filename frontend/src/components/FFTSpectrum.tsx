import { useMemo } from "react";
import { Area, AreaChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Radio } from "lucide-react";
import type { Alert, TemporalSummary } from "../types/alert";

type Props = { alerts: Alert[]; temporal: TemporalSummary | null };

export default function FFTSpectrum({ alerts, temporal }: Props) {
  const c2 = useMemo(() => alerts.find((alert) => alert.threatType === "C2 Beacon" && alert.beaconInterval), [alerts]);
  const interval = c2?.beaconInterval ?? null;
  const domFreq = interval ? 1 / interval : null;
  const c2Cv = c2?.indicators.find((indicator) => /inter-arrival cv/i.test(indicator))?.match(/([\d.]+)$/)?.[1];
  const periodicityCv = c2Cv == null ? temporal?.temporal_features?.inter_arrival_cv ?? 0 : Number(c2Cv);
  const eventCount = temporal?.total_events_observed ?? alerts.length;
  const c2Alerts = temporal?.alert_classes?.["C2 Beacon"] ?? alerts.filter((alert) => alert.threatType === "C2 Beacon").length;

  const spectrum = useMemo(() => {
    const pointCount = 60;
    const maxFrequency = 0.05;
    return Array.from({ length: pointCount }, (_, index) => {
      const frequency = (index / (pointCount - 1)) * maxFrequency;
      const noise = 0.025 + ((Math.sin((index + eventCount) * 1.71) + 1) / 2) * 0.03;
      let magnitude = noise;
      if (domFreq) {
        const peakStrength = Math.min(1, Math.max(0.2, 1 - periodicityCv));
        const fundamental = peakStrength * Math.exp(-(((frequency - domFreq) / 0.0016) ** 2));
        const harmonic = 0.35 * peakStrength * Math.exp(-(((frequency - domFreq * 2) / 0.0016) ** 2));
        magnitude = Math.max(magnitude, fundamental + harmonic);
      }
      return { frequency: +frequency.toFixed(4), magnitude: +magnitude.toFixed(3) };
    });
  }, [domFreq, eventCount, periodicityCv]);

  return (
    <section className="panel-base flex flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-[var(--bg-border)] px-4 py-3">
        <div className="flex items-center gap-2">
          <Radio size={14} className="text-[var(--text-muted)]" />
          <h2 className="text-[13px] font-semibold">C2 Beacon Spectrum</h2>
          <span className="label-mono text-[9px] text-[var(--text-dim)]">metadata FFT</span>
        </div>
        <div className="flex items-center gap-2">
          {eventCount > 0 && <span className="label-mono text-[8px] text-[var(--sev-low)]">LIVE</span>}
          {interval && <span className="mono text-[13px] text-[var(--sev-high)]">{interval.toFixed(1)}s</span>}
        </div>
      </div>

      <div className="relative min-h-[120px] flex-1 px-1 pt-2">
        {!interval && <div className="absolute inset-0 z-10 flex items-center justify-center"><p className="label-mono text-[9px] text-[var(--text-dim)]">No C2 periodicity in current window</p></div>}
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={spectrum} margin={{ top: 8, right: 10, bottom: 4, left: 0 }}>
            <defs>
              <linearGradient id="fftFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f97316" stopOpacity={interval ? 0.4 : 0.06} />
                <stop offset="100%" stopColor="#f97316" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="frequency" hide />
            <YAxis hide domain={[0, 1.2]} />
            <Tooltip
              contentStyle={{ background: "#0d1728", border: "1px solid rgba(179,202,230,.2)", borderRadius: 8, fontSize: 10 }}
              formatter={(value) => [`${Number(value).toFixed(3)} magnitude`, "signal"] as [string, string]}
              labelFormatter={(value) => `${Number(value).toFixed(4)} Hz`}
            />
            {domFreq && <ReferenceLine x={+domFreq.toFixed(4)} stroke="#f97316" strokeDasharray="3 3" label={{ value: `${domFreq.toFixed(4)} Hz`, position: "top", fill: "#f97316", fontSize: 9, fontFamily: "JetBrains Mono, monospace" }} />}
            <Area type="monotone" dataKey="magnitude" stroke={interval ? "#f97316" : "#526176"} strokeWidth={1.4} fill="url(#fftFill)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-3 gap-px border-t border-[var(--bg-border)] bg-[var(--bg-border)]">
        <Stat label="Dominant Hz" value={domFreq ? domFreq.toFixed(4) : "none"} />
        <Stat label="IAT CV" value={interval ? periodicityCv.toFixed(3) : "none"} />
        <Stat label="C2 alerts" value={c2Alerts.toLocaleString()} />
      </div>
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return <div className="bg-[var(--bg-surface)] px-3 py-2"><div className="label-mono text-[7.5px]">{label}</div><div className="mono mt-0.5 text-[11px]">{value}</div></div>;
}
