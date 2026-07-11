import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Cpu,
  Gauge,
  Radio,
  ShieldCheck,
  ShieldAlert,
  Waves,
  Zap,
  Network,
  HardDrive,
  Timer,
} from "lucide-react";
import ThroughputChart from "./ThroughputChart";
import ThreatStatus from "./ThreatStatus";
import AlertLog, { type AlertRow } from "./AlertLog";
import FlowFeed, { type FlowRow } from "./FlowFeed";
import StatCard from "./StatCard";

type ThroughputPoint = { t: number; label: string; bps: number; pps: number };

const THREAT_TYPES = [
  "DDoS · UDP Flood",
  "DDoS · TCP SYN",
  "DoS · HTTP Slowloris",
  "Botnet · Mirai Scan",
  "Botnet · C2 Beacon",
  "Reconnaissance · Port Scan",
] as const;

const SRC_POOL = [
  "192.168.4.17",
  "192.168.4.32",
  "10.0.0.45",
  "10.0.0.88",
  "172.16.9.101",
  "203.0.113.42",
  "198.51.100.7",
];
const DST_POOL = [
  "192.168.4.1",
  "192.168.4.2",
  "10.0.0.1",
  "10.0.0.10",
  "iot-hub.local",
  "gw.sentinel.iot",
];
const PROTOS = ["TCP", "UDP", "ICMP"] as const;

function pick<T>(arr: readonly T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function fmtTime(ts: number) {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function fmtBytes(b: number) {
  if (b < 1024) return `${b.toFixed(0)} B/s`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB/s`;
  return `${(b / (1024 * 1024)).toFixed(2)} MB/s`;
}

export default function Dashboard() {
  const [running, setRunning] = useState(true);
  const [series, setSeries] = useState<ThroughputPoint[]>([]);
  useEffect(() => {
    const now = Date.now();
    setSeries(
      Array.from({ length: 30 }, (_, i) => {
        const t = now - (30 - i) * 5000;
        return {
          t,
          label: fmtTime(t),
          bps: 40_000 + Math.random() * 30_000,
          pps: 40 + Math.random() * 40,
        };
      }),
    );
  }, []);
  const [flows, setFlows] = useState<FlowRow[]>([]);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [totalFlows, setTotalFlows] = useState(12_487);
  const [threats, setThreats] = useState(23);
  const [threatLevel, setThreatLevel] = useState<"secure" | "warning" | "critical">(
    "secure",
  );
  const [avgInference, setAvgInference] = useState(2.4);
  const criticalTimeoutRef = useRef<number | null>(null);

  // Simulated live inference tick — every 1.2s a new flow is classified.
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(() => {
      const isThreat = Math.random() < 0.14;
      const inference = +(1.4 + Math.random() * 3.2).toFixed(2);
      const src = pick(SRC_POOL);
      const dst = pick(DST_POOL);
      const proto = pick(PROTOS);
      const bytes = Math.floor(300 + Math.random() * (isThreat ? 180_000 : 8_000));
      const packets = Math.floor(4 + Math.random() * (isThreat ? 260 : 40));

      const flow: FlowRow = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        ts: Date.now(),
        src,
        dst,
        proto,
        packets,
        bytes,
        duration: +(0.3 + Math.random() * 4.7).toFixed(2),
        inference,
        verdict: isThreat ? 1 : 0,
      };

      setFlows((prev) => [flow, ...prev].slice(0, 40));
      setTotalFlows((n) => n + 1);
      setAvgInference((v) => +((v * 0.9 + inference * 0.1)).toFixed(2));

      if (isThreat) {
        const threat: AlertRow = {
          id: flow.id,
          ts: flow.ts,
          type: pick(THREAT_TYPES),
          src,
          dst,
          action: Math.random() < 0.7 ? "BLOCKED" : "QUARANTINED",
          inference,
          confidence: +(0.86 + Math.random() * 0.13).toFixed(3),
        };
        setAlerts((prev) => [threat, ...prev].slice(0, 50));
        setThreats((n) => n + 1);
        setThreatLevel("critical");
        if (criticalTimeoutRef.current) window.clearTimeout(criticalTimeoutRef.current);
        criticalTimeoutRef.current = window.setTimeout(() => {
          setThreatLevel((cur) => (cur === "critical" ? "warning" : cur));
          window.setTimeout(() => setThreatLevel("secure"), 4000);
        }, 5000);
      }
    }, 1200);
    return () => window.clearInterval(id);
  }, [running]);

  // Throughput chart tick — every 2s push a new sample.
  useEffect(() => {
    if (!running) return;
    const id = window.setInterval(() => {
      setSeries((prev) => {
        const last = prev[prev.length - 1]?.bps ?? 50_000;
        const drift = (Math.random() - 0.5) * 18_000;
        const spike = Math.random() < 0.08 ? Math.random() * 180_000 : 0;
        const bps = Math.max(8_000, last + drift + spike);
        const t = Date.now();
        const next = [
          ...prev,
          {
            t,
            label: fmtTime(t),
            bps,
            pps: 30 + bps / 900,
          },
        ];
        return next.slice(-40);
      });
    }, 2000);
    return () => window.clearInterval(id);
  }, [running]);

  const currentBps = series[series.length - 1]?.bps ?? 0;
  const peakBps = useMemo(() => Math.max(...series.map((p) => p.bps)), [series]);

  return (
    <div className="relative min-h-screen text-foreground">
      {/* Ambient grid backdrop */}
      <div className="pointer-events-none fixed inset-0 grid-bg" aria-hidden />

      <div className="relative mx-auto max-w-[1600px] px-6 py-6 lg:px-10 lg:py-8">
        <Header
          running={running}
          onToggle={() => setRunning((r) => !r)}
          threatLevel={threatLevel}
        />

        {/* Top stat strip */}
        <section className="mt-6 grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard
            icon={<Waves className="h-4 w-4" />}
            label="Live throughput"
            value={fmtBytes(currentBps)}
            sub={`Peak ${fmtBytes(peakBps)}`}
            tone="accent"
          />
          <StatCard
            icon={<Network className="h-4 w-4" />}
            label="Flows analyzed"
            value={totalFlows.toLocaleString()}
            sub="Since gateway boot"
            tone="primary"
          />
          <StatCard
            icon={<AlertTriangle className="h-4 w-4" />}
            label="Threats detected"
            value={threats.toString()}
            sub={`${((threats / totalFlows) * 100).toFixed(2)}% of flows`}
            tone="danger"
          />
          <StatCard
            icon={<Timer className="h-4 w-4" />}
            label="Avg inference"
            value={`${avgInference.toFixed(2)} ms`}
            sub="Per flow · Random Forest"
            tone="warning"
          />
        </section>

        {/* Main grid */}
        <section className="mt-6 grid gap-6 xl:grid-cols-3">
          <div className="xl:col-span-2 space-y-6">
            <div className="rounded-xl border border-border bg-card/70 backdrop-blur-sm">
              <div className="flex items-center justify-between border-b border-border px-5 py-3">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-primary" />
                  <h2 className="text-sm font-semibold tracking-wide uppercase text-foreground">
                    Network Throughput
                  </h2>
                </div>
                <div className="flex items-center gap-4 text-xs text-muted-foreground font-mono">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-primary" />
                    Bytes/sec
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-accent" />
                    Packets/sec
                  </span>
                </div>
              </div>
              <div className="p-4">
                <ThroughputChart data={series} />
              </div>
            </div>

            <FlowFeed rows={flows} />
          </div>

          <div className="space-y-6">
            <ThreatStatus level={threatLevel} lastAlert={alerts[0]?.ts ?? null} />

            <SystemPanel />
          </div>
        </section>

        <section className="mt-6">
          <AlertLog rows={alerts} />
        </section>

        <footer className="mt-10 flex flex-col items-start justify-between gap-2 border-t border-border pt-6 text-xs text-muted-foreground sm:flex-row sm:items-center">
          <p className="font-mono">
            SentinelIoT PoC · Random Forest · flow-window 5s · no DPI
          </p>
          <p className="font-mono">
            Edge node: <span className="text-foreground">rpi-gw-01</span> · sim mode
          </p>
        </footer>
      </div>
    </div>
  );
}

function Header({
  running,
  onToggle,
  threatLevel,
}: {
  running: boolean;
  onToggle: () => void;
  threatLevel: "secure" | "warning" | "critical";
}) {
  const statusColor =
    threatLevel === "critical"
      ? "bg-destructive"
      : threatLevel === "warning"
        ? "bg-[var(--warning)]"
        : "bg-primary";

  return (
    <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-4">
        <div className="relative flex h-11 w-11 items-center justify-center rounded-lg border border-primary/40 bg-primary/10 glow-primary">
          <ShieldCheck className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            SentinelIoT{" "}
            <span className="text-muted-foreground font-normal">/ IDS Console</span>
          </h1>
          <p className="text-xs text-muted-foreground font-mono">
            Lightweight ML intrusion detection · Edge gateway · Random Forest v1.3
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 rounded-md border border-border bg-card/60 px-3 py-2 font-mono text-xs">
          <span className={`h-2 w-2 rounded-full ${statusColor} pulse-dot`} />
          <span className="text-muted-foreground">STATE</span>
          <span className="text-foreground uppercase">{threatLevel}</span>
        </div>
        <button
          onClick={onToggle}
          className={`inline-flex items-center gap-2 rounded-md border px-3 py-2 text-xs font-mono uppercase tracking-wide transition-colors ${
            running
              ? "border-primary/50 bg-primary/10 text-primary hover:bg-primary/20"
              : "border-border bg-card text-muted-foreground hover:text-foreground"
          }`}
        >
          <Radio className="h-3.5 w-3.5" />
          {running ? "Sniffing" : "Paused"}
        </button>
      </div>
    </header>
  );
}

function SystemPanel() {
  const [cpu, setCpu] = useState(31);
  const [mem, setMem] = useState(412);
  useEffect(() => {
    const id = window.setInterval(() => {
      setCpu((v) => Math.min(88, Math.max(12, v + (Math.random() - 0.5) * 12)));
      setMem((v) => Math.min(920, Math.max(300, v + (Math.random() - 0.5) * 40)));
    }, 2000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="rounded-xl border border-border bg-card/70 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <Gauge className="h-4 w-4 text-accent" />
          <h2 className="text-sm font-semibold tracking-wide uppercase">
            Edge Node Health
          </h2>
        </div>
        <span className="text-[10px] font-mono text-muted-foreground uppercase">
          rpi-4 · 1 GB · 2 core
        </span>
      </div>
      <div className="space-y-4 p-5">
        <Meter
          icon={<Cpu className="h-3.5 w-3.5" />}
          label="CPU"
          value={cpu}
          max={100}
          unit="%"
          warn={70}
        />
        <Meter
          icon={<HardDrive className="h-3.5 w-3.5" />}
          label="RAM"
          value={mem}
          max={1024}
          unit=" MB"
          warn={800}
        />
        <div className="grid grid-cols-2 gap-3 pt-2">
          <MiniStat
            icon={<Zap className="h-3.5 w-3.5" />}
            label="Model size"
            value="1.8 MB"
          />
          <MiniStat
            icon={<Timer className="h-3.5 w-3.5" />}
            label="Flow window"
            value="5.0 s"
          />
        </div>
      </div>
    </div>
  );
}

function Meter({
  icon,
  label,
  value,
  max,
  unit,
  warn,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  max: number;
  unit: string;
  warn: number;
}) {
  const pct = Math.min(100, (value / max) * 100);
  const color = value >= warn ? "bg-[var(--warning)]" : "bg-primary";
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between text-xs font-mono">
        <span className="flex items-center gap-1.5 text-muted-foreground">
          {icon}
          {label}
        </span>
        <span className="text-foreground">
          {value.toFixed(0)}
          {unit}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
        <div
          className={`h-full ${color} transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function MiniStat({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-md border border-border bg-background/50 p-2.5">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground font-mono">
        {icon}
        {label}
      </div>
      <div className="mt-1 font-mono text-sm text-foreground">{value}</div>
    </div>
  );
}