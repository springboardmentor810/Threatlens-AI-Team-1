import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";

const PALETTE = ["#22d3ee", "#3b82f6", "#a855f7", "#f43f5e", "#facc15", "#34d399"];

export default function PieChartCard({
  title,
  data,
}: {
  title: string;
  data: { name: string; value: number; color?: string }[];
}) {
  return (
    <Card className="h-[340px]">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <ResponsiveContainer width="100%" height="85%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={55}
            outerRadius={85}
            paddingAngle={3}
            stroke="none"
          >
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color || PALETTE[i % PALETTE.length]} />
            ))}
          </Pie>
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
          <Legend wrapperStyle={{ fontSize: "12px", color: "rgb(var(--c-slate-300))" }} />
        </PieChart>
      </ResponsiveContainer>
    </Card>
  );
}
