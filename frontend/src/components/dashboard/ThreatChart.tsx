import { useMemo } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { Process } from "@/data/initialData";

interface ThreatChartProps {
  processes: Process[];
}

export default function ThreatChart({ processes }: ThreatChartProps) {
  const chartData = useMemo(() => {
    return [...processes]
      .sort((a, b) => b.ThreatScore - a.ThreatScore)
      .slice(0, 10)
      .map((p) => ({
        name: `${p.ImageFileName} (${p.PID})`,
        score: p.ThreatScore,
      }));
  }, [processes]);

  function getBarColor(score: number) {
    if (score >= 7) return "hsl(0, 90%, 45%)";
    if (score > 3) return "hsl(0, 85%, 55%)";
    if (score > 1.5) return "hsl(40, 95%, 55%)";
    return "hsl(200, 100%, 50%)";
  }

  return (
    <div className="glass rounded-lg p-5">
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        Top Processes by Threat Score
      </h3>
      <div className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 20 }}>
            <XAxis
              type="number"
              domain={[0, 10]}
              tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11, fontFamily: "JetBrains Mono" }}
              axisLine={{ stroke: "hsl(var(--border))" }}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={160}
              tick={{ fill: "hsl(var(--foreground))", fontSize: 11, fontFamily: "JetBrains Mono" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                borderRadius: "8px",
                fontFamily: "JetBrains Mono",
                fontSize: "12px",
                color: "hsl(var(--foreground))",
              }}
              formatter={(value: number) => [value.toFixed(1), "Threat Score"]}
              cursor={{ fill: "hsl(var(--primary) / 0.05)" }}
            />
            <Bar dataKey="score" radius={[0, 4, 4, 0]} barSize={18}>
              {chartData.map((entry, i) => (
                <Cell key={i} fill={getBarColor(entry.score)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
