import { Threat } from "@/types/threat.types";
import axiosInstance from "./axiosInstance";
import { ThreatLogResponse, toThreat } from "./mappers";

interface PaginatedThreats {
  items: ThreatLogResponse[];
  total: number;
  page: number;
  page_size: number;
}

export const threatApi = {
  getThreats: async (): Promise<Threat[]> => {
    const { data } = await axiosInstance.get<PaginatedThreats>("/threats", {
      params: { page: 1, page_size: 100 },
    });
    return data.items.map(toThreat);
  },

  /**
   * Resolve the sentinel the sidebar links to. "Threat Details" is a detail
   * view with no natural landing id; it used to point at the fixture id
   * "thr-1001", which does not exist once the data is real.
   */
  getLatestThreatId: async (): Promise<string | undefined> => {
    const { data } = await axiosInstance.get<PaginatedThreats>("/threats", {
      params: { page: 1, page_size: 1 },
    });
    return data.items[0] ? String(data.items[0].id) : undefined;
  },

  getThreatById: async (id: string): Promise<Threat | undefined> => {
    if (id === "latest") {
      const latest = await threatApi.getLatestThreatId();
      if (!latest) return undefined;
      id = latest;
    }

    const { data } = await axiosInstance.get<ThreatLogResponse>(`/threats/${id}`);
    const threat = toThreat(data);

    // The timeline lives on its own endpoint. A detection without one is
    // normal (it is written asynchronously), so a failure here must not lose
    // the threat itself.
    try {
      const { data: events } = await axiosInstance.get<
        { created_at: string; description: string }[]
      >(`/threats/timeline/${id}`);
      threat.timeline = events.map((e) => ({
        time: e.created_at,
        event: e.description,
      }));
    } catch {
      threat.timeline = [];
    }

    return threat;
  },

  downloadReportPdf: async (threatId: string, threatName?: string): Promise<void> => {
    const { reportsApi } = await import("./reportsApi");
    return reportsApi.downloadReportPdf(threatId, threatName);
  },
};
