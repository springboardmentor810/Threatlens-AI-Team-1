import axiosInstance from "./axiosInstance";
import { ThreatLogResponse, toRecentScan } from "./mappers";
import { DashboardStats } from "@/types/dashboard.types";

interface SummaryResponse {
  total_files: number;
  malware_files: number;
  benign_files: number;
  critical_threats: number;
  high_risk_threats: number;
  medium_risk_threats: number;
  low_risk_threats: number;
  active_threats: number;
}

interface TrendsResponse {
  days: number;
  data: { date: string; total: number; malware: number; benign: number }[];
}

interface FamiliesResponse {
  total_malware: number;
  families: { family: string; count: number; percentage: number }[];
}

interface PaginatedThreats {
  items: ThreatLogResponse[];
  total: number;
}

interface ActivityItem {
  id: string;
  actor: string;
  action: string;
  time: string | null;
}

/** Severity colours the pie chart reuses; matches tailwind.config.js. */
const SEVERITY_COLORS = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#facc15",
  low: "#34d399",
} as const;

/**
 * Every panel on the dashboard and analytics pages, assembled from the API.
 *
 * The key names below are the contract the chart components read (see
 * AnalyticsPage.tsx: `barKey="detections"`, the critical/high/medium line keys,
 * and so on). Getting one wrong renders an empty chart rather than an error,
 * so they are worth keeping aligned with that file.
 */
export const analyticsApi = {
  getDashboardBundle: async () => {
    const [summary, threats, activity] = await Promise.all([
      axiosInstance.get<SummaryResponse>("/threats/dashboard/summary"),
      axiosInstance.get<PaginatedThreats>("/threats", {
        params: { page: 1, page_size: 5 },
      }),
      axiosInstance.get<ActivityItem[]>("/analytics/activity", {
        params: { limit: 8 },
      }),
    ]);

    const s = summary.data;
    const stats: DashboardStats = {
      totalFilesScanned: s.total_files,
      malwareDetected: s.malware_files,
      safeFiles: s.benign_files,
      threatScore: s.total_files
        ? Math.round((s.malware_files / s.total_files) * 100)
        : 0,
      todaysScans: s.total_files,
      activeAlerts: s.active_threats,
    };

    return {
      stats,
      recentActivity: activity.data.map((a) => ({
        id: a.id,
        actor: a.actor,
        action: a.action,
        time: a.time ?? "",
      })),
      recentScans: threats.data.items.map(toRecentScan),
    };
  },

  getAnalyticsBundle: async () => {
    const [summary, trends, families, weekly, classification, heatmap, performance] =
      await Promise.all([
        axiosInstance.get<SummaryResponse>("/threats/dashboard/summary"),
        axiosInstance.get<TrendsResponse>("/threats/dashboard/trends", {
          params: { days: 30 },
        }),
        axiosInstance.get<FamiliesResponse>("/threats/dashboard/families", {
          params: { limit: 6 },
        }),
        axiosInstance.get<{ day: string; uploads: number }[]>("/analytics/weekly-uploads"),
        axiosInstance.get<{ name: string; value: number }[]>("/analytics/classification"),
        axiosInstance.get<number[][]>("/analytics/heatmap"),
        axiosInstance.get<{ metric: string; value: number }[]>(
          "/analytics/model-performance"
        ),
      ]);

    const s = summary.data;

    return {
      // AreaChartCard plots areaKey="malware".
      monthlyThreatDetection: trends.data.data.map((p) => ({
        month: p.date,
        malware: p.malware,
        safe: p.benign,
      })),

      // PieChartCard reads {name, value, color}.
      threatLevelDistribution: [
        { name: "Critical", value: s.critical_threats, color: SEVERITY_COLORS.critical },
        { name: "High", value: s.high_risk_threats, color: SEVERITY_COLORS.high },
        { name: "Medium", value: s.medium_risk_threats, color: SEVERITY_COLORS.medium },
        { name: "Low", value: s.low_risk_threats, color: SEVERITY_COLORS.low },
      ],

      // BarChartCard plots barKey="detections", not "count".
      topMalwareFamilies: families.data.families.map((f) => ({
        family: f.family,
        detections: f.count,
      })),

      riskScoreDistribution: [
        { range: "0-25", count: s.low_risk_threats },
        { range: "26-50", count: s.medium_risk_threats },
        { range: "51-75", count: s.high_risk_threats },
        { range: "76-100", count: s.critical_threats },
      ],

      // LineChartCard plots three series keyed critical/high/medium. The trend
      // endpoint reports totals per day, so severity is apportioned by the
      // current mix rather than stored per day.
      threatTrend: trends.data.data.map((p) => {
        const malware = p.malware;
        const totalRisk =
          s.critical_threats + s.high_risk_threats + s.medium_risk_threats || 1;
        return {
          date: p.date,
          critical: Math.round((malware * s.critical_threats) / totalRisk),
          high: Math.round((malware * s.high_risk_threats) / totalRisk),
          medium: Math.round((malware * s.medium_risk_threats) / totalRisk),
        };
      }),

      weeklyUploads: weekly.data,
      classificationResults: classification.data,
      scanHeatmap: heatmap.data,
      detectionEngineRadar: performance.data,
    };
  },
};
