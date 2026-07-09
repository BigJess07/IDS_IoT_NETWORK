import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";

type Level = "secure" | "warning" | "critical";

export default function ThreatStatus({
  level,
  lastAlert,
}: {
  level: Level;
  lastAlert: number | null;
}) {
  const config = {
    secure: {
      label: "SECURE",
      sub: "No anomalies detected in the active window.",
      icon: <ShieldCheck className="h-8 w-8" />,
      border: "border-primary/40",
      bar: "bg-primary",
      text: "text-primary",
      pulse: "bg-primary/10",
      glow: "glow-primary",
    },
    warning: {
      label: "ELEVATED",
      sub: "Suspicious flow signatures observed — monitoring.",
      icon: <ShieldQuestion className="h-8 w-8" />,
      border: "border-[var(--warning)]/50",
      bar: "bg-[var(--warning)]",
      text: "text-[var(--warning)]",
      pulse: "bg-[var(--warning)]/10",
      glow: "",
    },
    critical: {
      label: "CRITICAL THREAT DETECTED",
      sub: "Malicious flow classified — mitigation dispatched.",
      icon: <ShieldAlert className="h-8 w-8" />,
      border: "border-destructive/60",
      bar: "bg-destructive",
      text: "text-destructive",
      pulse: "bg-destructive/15",
      glow: "glow-danger",
    },
  }[level];

  return (
    <div
      className={`relative overflow-hidden rounded-xl border ${config.border} bg-card/80 p-6 backdrop-blur-sm ${config.glow}`}
    >
      <div className={`absolute inset-x-0 top-0 h-1 ${config.bar}`} />
      <div className="flex items-start gap-4">
        <div
          className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-lg ${config.pulse} ${config.text}`}
        >
          {config.icon}
        </div>
        <div className="min-w-0">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            Gateway status
          </div>
          <div className={`mt-1 text-lg font-semibold tracking-tight ${config.text}`}>
            {config.label}
          </div>
          <p className="mt-1 text-xs text-muted-foreground leading-relaxed">
            {config.sub}
          </p>
          <div className="mt-4 flex items-center gap-2 text-[11px] font-mono text-muted-foreground">
            <span className={`h-2 w-2 rounded-full ${config.bar} pulse-dot`} />
            <span>
              LAST ALERT:{" "}
              <span className="text-foreground">
                {lastAlert
                  ? new Date(lastAlert).toLocaleTimeString("en-GB", { hour12: false })
                  : "—"}
              </span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}