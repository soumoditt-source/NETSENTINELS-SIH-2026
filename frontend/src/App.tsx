import { useMemo, useState } from "react";
import { useThreatFeed } from "./data/useThreatFeed";
import { SEVERITY_RANK } from "./types/alert";
import type { Alert } from "./types/alert";
import Header from "./components/Header";
import ThreatGraph from "./components/ThreatGraph";
import CriticalAlertPanel from "./components/CriticalAlertPanel";
import AlertFeed from "./components/AlertFeed";
import TrafficCharts from "./components/TrafficCharts";
import MitreHeatmap from "./components/MitreHeatmap";
import ModelCards from "./components/ModelCards";
import AttackTimeline from "./components/AttackTimeline";
import FFTSpectrum from "./components/FFTSpectrum";
import ConfidenceBands from "./components/ConfidenceBands";
import AlertDetailModal from "./components/AlertDetailModal";
import ExplainMode from "./components/ExplainMode";
import DataEvidencePanel from "./components/DataEvidencePanel";
import TemporalForensicsPanel from "./components/TemporalForensicsPanel";
import LaunchTelemetryPanel from "./components/LaunchTelemetryPanel";
import ThreatCoveragePanel from "./components/ThreatCoveragePanel";

export default function App() {
  const feed = useThreatFeed();
  const [selected, setSelected] = useState<Alert | null>(null);
  const [mode, setMode] = useState<"explain" | "soc">("soc");

  // The most severe recent threat drives the critical panel.
  const critical = useMemo(() => {
    const threats = feed.alerts.filter((a) => a.threatType !== "Benign");
    if (threats.length === 0) return null;
    return [...threats].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.timestamp - a.timestamp,
    )[0];
  }, [feed.alerts]);

  return (
    <div className="relative min-h-full text-[var(--text-main)]">
      <div className="bg-criss-cross pointer-events-none fixed inset-0 -z-10" />

      <Header
        status={feed.status}
        flowsPerSec={feed.flowsPerSec}
        totalFlows={feed.totalFlows}
        phase={feed.phase}
        source={feed.source}
        mode={mode}
        onModeChange={setMode}
      />

      <main className="mx-auto max-w-[1600px] p-4 lg:p-6 grid gap-4 lg:gap-5">
        {mode === "explain" ? (
          <>
            <ExplainMode feed={feed} onInspect={setSelected} />
            <LaunchTelemetryPanel liveEvents={feed.temporal?.events_in_window ?? 0} />
          </>
        ) : (
          <>
        {/* Top: 3D graph + critical panel */}
        <div className="grid gap-4 lg:gap-5 lg:grid-cols-[1.55fr_1fr]">
          <div className="animate-entrance stagger-1 min-h-[360px] flex">
            <div className="flex-1 flex">
              <ThreatGraph alerts={feed.alerts} />
            </div>
          </div>
          <div className="animate-entrance stagger-2 min-h-[360px] flex">
            <div className="flex-1 flex">
              <CriticalAlertPanel alert={critical} onInspect={setSelected} />
            </div>
          </div>
        </div>

        <div className="animate-entrance stagger-3">
          <TemporalForensicsPanel summary={feed.temporal} />
        </div>

        <div className="animate-entrance stagger-4">
          <DataEvidencePanel training={feed.training} />
        </div>

        <div className="animate-entrance stagger-5">
          <LaunchTelemetryPanel liveEvents={feed.temporal?.events_in_window ?? 0} />
        </div>

        <div className="animate-entrance stagger-6">
          <ThreatCoveragePanel />
        </div>

        {/* Attack story: rolling swimlane */}
        <div className="animate-entrance stagger-3 min-h-[200px] flex">
          <div className="flex-1 flex">
            <AttackTimeline alerts={feed.alerts} />
          </div>
        </div>

        {/* Live feed */}
        <div className="animate-entrance stagger-4 h-[300px] flex">
          <div className="flex-1 flex">
            <AlertFeed alerts={feed.alerts} onSelect={setSelected} />
          </div>
        </div>

        {/* Model intelligence: traffic · FFT spectrum · confidence */}
        <div className="grid gap-4 lg:gap-5 lg:grid-cols-3">
          <div className="animate-entrance stagger-5 min-h-[260px] flex">
            <div className="flex-1 flex">
              <TrafficCharts data={feed.packetRate} />
            </div>
          </div>
          <div className="animate-entrance stagger-6 min-h-[260px] flex">
            <div className="flex-1 flex">
              <FFTSpectrum alerts={feed.alerts} temporal={feed.temporal} />
            </div>
          </div>
          <div className="animate-entrance stagger-7 min-h-[260px] flex">
            <div className="flex-1 flex">
              <ConfidenceBands models={feed.models} />
            </div>
          </div>
        </div>

        {/* Coverage: MITRE · models */}
        <div className="grid gap-4 lg:gap-5 lg:grid-cols-2">
          <div className="animate-entrance stagger-7 min-h-[280px] flex">
            <div className="flex-1 flex">
              <MitreHeatmap cells={feed.mitre} />
            </div>
          </div>
          <div className="animate-entrance stagger-8 min-h-[280px] flex">
            <div className="flex-1 flex">
              <ModelCards models={feed.models} />
            </div>
          </div>
        </div>
          </>
        )}
      </main>

      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
