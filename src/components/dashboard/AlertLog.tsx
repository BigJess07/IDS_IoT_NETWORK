import { AlertTriangle, ShieldOff, Ban } from "lucide-react";

export type AlertRow = {
  id: string;
  ts: number;
  type: string;
  src: string;
  dst: string;
  action: "BLOCKED" | "QUARANTINED";
  inference: number;
  confidence: number;
};

function fmt(ts: number) {
  return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
}

export default function AlertLog({ rows }: { rows: AlertRow[] }) {
  return (
    <div className="rounded-xl border border-border bg-card/70 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-destructive" />
          <h2 className="text-sm font-semibold tracking-wide uppercase">
            Security Alert Log
          </h2>
          <span className="ml-2 rounded-md border border-destructive/40 bg-destructive/10 px-1.5 py-0.5 font-mono text-[10px] text-destructive">
            {rows.length}
          </span>
        </div>
        <span className="text-[10px] font-mono uppercase text-muted-foreground">
          Newest first · retention 50
        </span>
      </div>

      <div className="max-h-[380px] overflow-y-auto">
        <table className="w-full text-left font-mono text-xs">
          <thead className="sticky top-0 bg-card/95 backdrop-blur">
            <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="px-5 py-2.5 font-normal">Timestamp</th>
              <th className="px-3 py-2.5 font-normal">Threat</th>
              <th className="px-3 py-2.5 font-normal">Source</th>
              <th className="px-3 py-2.5 font-normal">Destination</th>
              <th className="px-3 py-2.5 font-normal">Confidence</th>
              <th className="px-3 py-2.5 font-normal">Inference</th>
              <th className="px-5 py-2.5 font-normal">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={7}
                  className="px-5 py-10 text-center text-muted-foreground"
                >
                  No threats detected — all flows classified as benign.
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr
                key={r.id}
                className="border-t border-border/60 transition-colors hover:bg-secondary/40"
              >
                <td className="px-5 py-2.5 text-muted-foreground">{fmt(r.ts)}</td>
                <td className="px-3 py-2.5">
                  <span className="inline-flex items-center gap-1.5 text-destructive">
                    <span className="h-1.5 w-1.5 rounded-full bg-destructive" />
                    {r.type}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-foreground">{r.src}</td>
                <td className="px-3 py-2.5 text-foreground">{r.dst}</td>
                <td className="px-3 py-2.5">
                  <span className="text-primary">
                    {(r.confidence * 100).toFixed(1)}%
                  </span>
                </td>
                <td className="px-3 py-2.5 text-muted-foreground">
                  {r.inference.toFixed(2)} ms
                </td>
                <td className="px-5 py-2.5">
                  <span
                    className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] uppercase tracking-wider ${
                      r.action === "BLOCKED"
                        ? "border-destructive/40 bg-destructive/10 text-destructive"
                        : "border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[var(--warning)]"
                    }`}
                  >
                    {r.action === "BLOCKED" ? (
                      <Ban className="h-3 w-3" />
                    ) : (
                      <ShieldOff className="h-3 w-3" />
                    )}
                    {r.action}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}