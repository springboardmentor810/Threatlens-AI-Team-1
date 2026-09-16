import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";

const chartTooltipStyle = {
  backgroundColor: "rgb(var(--c-surface))",
  border: "1px solid rgb(var(--c-border) / 0.15)",
  borderRadius: "10px",
  fontSize: "12px",
  color: "rgb(var(--c-slate-100))",
  boxShadow: "0 4px 12px rgba(0, 0, 0, 0.1)",
};

export default function LineChartCard({
  title,
  data,
  lines,
  xKey,
}: {
  title: string;
  // Recharts rows: one object per point, keyed by the axis/series names.
  data: Record<string, string | number>[];
  lines: { key: string; color: string; name: string }[];
  xKey: string;
}) {
  return (
    <Card className="h-[340px]">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <ResponsiveContainer width="100%" height="85%">
        <LineChart data={data} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
          <XAxis dataKey={xKey} stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
          <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
          <Tooltip
            contentStyle={chartTooltipStyle}
            itemStyle={{ color: "rgb(var(--c-slate-100))" }}
            labelStyle={{ color: "rgb(var(--c-slate-300))" }}
          />
          <Legend wrapperStyle={{ fontSize: "12px", color: "rgb(var(--c-slate-300))" }} />
          {lines.map((l) => (
            <Line
              key={l.key}
              type="monotone"
              dataKey={l.key}
              name={l.name}
              stroke={l.color}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
}
