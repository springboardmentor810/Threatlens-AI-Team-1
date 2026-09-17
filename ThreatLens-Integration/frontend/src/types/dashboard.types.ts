import { Severity } from "@/types/threat.types";

/**
 * One row of the "Recent Scans" panel.
 *
 * riskLevel is the Badge vocabulary rather than a bare string, so the two
 * `as any` casts that used to bridge the source data and the component are
 * no longer needed.
 */
export interface RecentScan {
  id: string;
  fileName: string;
  riskLevel: Severity | "safe" | "unscanned";
  time: string;
}

export interface DashboardStats {
  totalFilesScanned: number;
  malwareDetected: number;
  safeFiles: number;
  threatScore: number;
  todaysScans: number;
  activeAlerts: number;
}
