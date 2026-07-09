import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Point = { t: number; label: string; bps: number; pps: number };

function fmtBytes(v: number) {
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `${(v / 1_000).toFixed(0)}k`;
  return v.toFixed(0);
}

export default function ThroughputChart({ data }: { data: Point[] }) {
  return (
    <div className="h-[280px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 10, right: 10, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id="bpsFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-primary)" stopOpacity={0.55} />
              <stop offset="100%" stopColor="var(--color-primary)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 6" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: "var(--color-muted-foreground)", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "var(--color-border)" }}
            tickLine={false}
            interval="preserveEnd"
            minTickGap={40}
          />
          <YAxis
            yAxisId="bps"
            tickFormatter={fmtBytes}
            tick={{ fill: "var(--color-muted-foreground)", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "var(--color-border)" }}
            tickLine={false}
            width={48}
          />
          <YAxis
            yAxisId="pps"
            orientation="right"
            tick={{ fill: "var(--color-muted-foreground)", fontSize: 10, fontFamily: "JetBrains Mono" }}
            axisLine={{ stroke: "var(--color-border)" }}
            tickLine={false}
            width={36}
          />
          <Tooltip
            contentStyle={{
              background: "var(--color-popover)",
              border: "1px solid var(--color-border)",
              borderRadius: 8,
              fontFamily: "JetBrains Mono",
              fontSize: 12,
            }}
            labelStyle={{ color: "var(--color-muted-foreground)" }}
            formatter={(value: number, name) => {
              if (name === "bps") return [`${fmtBytes(value)} B/s`, "Bytes/s"];
              return [`${value.toFixed(0)}`, "Packets/s"];
            }}
          />
          <Area
            yAxisId="bps"
            type="monotone"
            dataKey="bps"
            stroke="var(--color-primary)"
            strokeWidth={2}
            fill="url(#bpsFill)"
            isAnimationActive={false}
          />
          <Line
            yAxisId="pps"
            type="monotone"
            dataKey="pps"
            stroke="var(--color-accent)"
            strokeWidth={1.5}
            dot={false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}