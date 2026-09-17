import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, ResponsiveContainer, Tooltip } from "recharts";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";

export default function RadarChartCard({
  title,
  data,
}: {
  title: string;
  data: { metric: string; value: number }[];
}) {
  return (
    <Card className="h-[340px]">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <ResponsiveContainer width="100%" height="85%">
        <RadarChart data={data}>
          <PolarGrid stroke="rgba(148,163,184,0.15)" />
          <PolarAngleAxis dataKey="metric" stroke="#64748b" fontSize={11} />
          <PolarRadiusAxis stroke="rgba(148,163,184,0.15)" fontSize={10} tick={false} />
          <Radar dataKey="value" stroke="#a855f7" fill="#a855f7" fillOpacity={0.35} />
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
          />
        </RadarChart>
      </ResponsiveContainer>
    </Card>
  );
}
