import { Network } from "lucide-react";

export type FlowRow = {
  id: string;
  ts: number;
  src: string;
  dst: string;
  proto: "TCP" | "UDP" | "ICMP";
  packets: number;
  bytes: number;
  duration: number;
  inference: number;
  verdict: 0 | 1;
};

function fmt(ts: number) {
  return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
}
function fmtBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(2)} MB`;
}

export default function FlowFeed({ rows }: { rows: FlowRow[] }) {
  return (
    <div className="rounded-xl border border-border bg-card/70 backdrop-blur-sm">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-accent" />
          <h2 className="text-sm font-semibold tracking-wide uppercase">
            Live Flow Classification
          </h2>
        </div>
        <span className="text-[10px] font-mono uppercase text-muted-foreground">
          5s temporal window · no DPI
        </span>
      </div>
      <div className="max-h-[340px] overflow-y-auto">
        <table className="w-full text-left font-mono text-xs">
          <thead className="sticky top-0 bg-card/95 backdrop-blur">
            <tr className="text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="px-5 py-2.5 font-normal">Time</th>
              <th className="px-3 py-2.5 font-normal">Proto</th>
              <th className="px-3 py-2.5 font-normal">Src → Dst</th>
              <th className="px-3 py-2.5 font-normal text-right">Pkts</th>
              <th className="px-3 py-2.5 font-normal text-right">Bytes</th>
              <th className="px-3 py-2.5 font-normal text-right">Dur</th>
              <th className="px-3 py-2.5 font-normal text-right">Infer</th>
              <th className="px-5 py-2.5 font-normal">Verdict</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={8}
                  className="px-5 py-10 text-center text-muted-foreground"
                >
                  Awaiting first classified flow…
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr
                key={r.id}
                className="border-t border-border/60 transition-colors hover:bg-secondary/40"
              >
                <td className="px-5 py-2 text-muted-foreground">{fmt(r.ts)}</td>
                <td className="px-3 py-2">
                  <span className="rounded border border-border bg-secondary/60 px-1.5 py-0.5 text-[10px] text-foreground">
                    {r.proto}
                  </span>
                </td>
                <td className="px-3 py-2 text-foreground">
                  {r.src}{" "}
                  <span className="text-muted-foreground">→</span> {r.dst}
                </td>
                <td className="px-3 py-2 text-right tabular-nums">{r.packets}</td>
                <td className="px-3 py-2 text-right tabular-nums">
                  {fmtBytes(r.bytes)}
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
                  {r.duration.toFixed(2)}s
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
                  {r.inference.toFixed(2)}ms
                </td>
                <td className="px-5 py-2">
                  {r.verdict === 1 ? (
                    <span className="inline-flex items-center gap-1 rounded border border-destructive/40 bg-destructive/10 px-1.5 py-0.5 text-[10px] uppercase text-destructive">
                      Malicious
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] uppercase text-primary">
                      Benign
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}