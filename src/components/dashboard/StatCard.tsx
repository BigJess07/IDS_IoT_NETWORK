import { type ReactNode } from "react";

type Tone = "primary" | "accent" | "danger" | "warning";

const toneMap: Record<Tone, { ring: string; icon: string; glow: string }> = {
  primary: {
    ring: "border-primary/30",
    icon: "text-primary bg-primary/10",
    glow: "before:bg-primary/40",
  },
  accent: {
    ring: "border-accent/30",
    icon: "text-accent bg-accent/10",
    glow: "before:bg-accent/40",
  },
  danger: {
    ring: "border-destructive/30",
    icon: "text-destructive bg-destructive/10",
    glow: "before:bg-destructive/40",
  },
  warning: {
    ring: "border-[var(--warning)]/30",
    icon: "text-[var(--warning)] bg-[var(--warning)]/10",
    glow: "before:bg-[var(--warning)]/40",
  },
};

export default function StatCard({
  icon,
  label,
  value,
  sub,
  tone = "primary",
}: {
  icon: ReactNode;
  label: string;
  value: string;
  sub?: string;
  tone?: Tone;
}) {
  const t = toneMap[tone];
  return (
    <div
      className={`relative overflow-hidden rounded-xl border ${t.ring} bg-card/70 p-4 backdrop-blur-sm before:absolute before:-top-8 before:-right-8 before:h-24 before:w-24 before:rounded-full before:blur-2xl before:opacity-40 ${t.glow}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        <span
          className={`flex h-7 w-7 items-center justify-center rounded-md ${t.icon}`}
        >
          {icon}
        </span>
      </div>
      <div className="mt-3 font-mono text-2xl font-semibold text-foreground tabular-nums">
        {value}
      </div>
      {sub && (
        <div className="mt-1 text-xs text-muted-foreground font-mono">{sub}</div>
      )}
    </div>
  );
}