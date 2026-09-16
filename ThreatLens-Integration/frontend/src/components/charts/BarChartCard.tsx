import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";

export default function BarChartCard({
  title,
  data,
  barKey,
  xKey,
  color = "#3b82f6",
  colors,
  layout = "horizontal",
}: {
  title: string;
  // Recharts rows: one object per point, keyed by the axis/series names.
  data: Record<string, string | number>[];
  barKey: string;
  xKey: string;
  color?: string;
  colors?: string[];
  layout?: "horizontal" | "vertical";
}) {
  return (
    <Card className="h-[340px]">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <ResponsiveContainer width="100%" height="85%">
        <BarChart
          data={data}
          layout={layout}
          margin={{ top: 4, right: 8, left: layout === "vertical" ? 40 : -12, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" />
          {layout === "horizontal" ? (
            <>
              <XAxis dataKey={xKey} stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
            </>
          ) : (
            <>
              <XAxis type="number" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis dataKey={xKey} type="category" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} width={90} />
            </>
          )}
          <Tooltip
            contentStyle={{
              backgroundColor: "rgb(var(--c-surface))",
              border: "1px solid rgb(var(--c-border) / 0.15)",
              borderRadius: "10px",
              fontSize: "12px",
              color: "rgb(var(--c-slate-100))",
              boxShadow: "0 4px 12px rgba(0, 0, 0, 0.1)",
            }}
            itemStyle={{ color: "rgb(var(--c-slate-100))" }}
            labelStyle={{ color: "rgb(var(--c-slate-300))" }}
            cursor={{ fill: "rgb(var(--c-overlay) / 0.05)" }}
          />
          <Bar dataKey={barKey} radius={[6, 6, 6, 6]}>
            {data.map((_, i) => (
              <Cell key={i} fill={colors ? colors[i % colors.length] : color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Card>
  );
}
