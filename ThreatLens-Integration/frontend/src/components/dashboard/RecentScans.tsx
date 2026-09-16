import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import Badge from "@/components/ui/Badge";
import { RecentScan } from "@/types/dashboard.types";
import { FileSearch } from "lucide-react";
import { timeAgo } from "@/utils/formatters";

export default function RecentScans({
  items,
}: {
  // The shared RecentScan type, so the badge vocabulary cannot drift between
  // this component and the mapper that feeds it.
  items: readonly RecentScan[];
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
        <FileSearch className="h-4 w-4 text-muted" />
      </CardHeader>
      <ul className="space-y-3">
        {items.map((item) => (
          <li key={item.id} className="flex items-center justify-between gap-3 text-sm">
            <div className="min-w-0">
              <p className="text-slate-200 truncate font-mono text-xs">{item.fileName}</p>
              <p className="text-xs text-muted mt-0.5">{timeAgo(item.time)}</p>
            </div>
            <Badge severity={item.riskLevel} />
          </li>
        ))}
      </ul>
    </Card>
  );
}
