import { Report } from "@/types/report.types";
import axiosInstance from "./axiosInstance";
import { ThreatLogResponse, toReport } from "./mappers";

interface PaginatedThreats {
  items: ThreatLogResponse[];
  total: number;
}

function triggerDownload(blob: Blob, defaultFilename: string, contentDisposition?: string) {
  let filename = defaultFilename;
  if (contentDisposition) {
    const match = contentDisposition.match(/filename="?([^"]+)"?/);
    if (match && match[1]) {
      filename = match[1];
    }
  }

  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

export const reportsApi = {
  getReports: async (): Promise<Report[]> => {
    const { data } = await axiosInstance.get<PaginatedThreats>("/threats", {
      params: { page: 1, page_size: 100 },
    });
    return data.items.map(toReport);
  },

  deleteReport: async (id: string): Promise<{ id: string }> => {
    await axiosInstance.delete(`/threats/${id}`);
    return { id };
  },

  exportCsv: async (): Promise<void> => {
    const response = await axiosInstance.get("/threats/export/csv", {
      responseType: "blob",
    });
    const defaultName = `threatlens_reports_${new Date().toISOString().slice(0, 10)}.csv`;
    triggerDownload(response.data, defaultName, response.headers["content-disposition"]);
  },

  downloadSummaryPdf: async (days: number = 30): Promise<void> => {
    const response = await axiosInstance.get("/threats/reports/summary/pdf", {
      params: { days },
      responseType: "blob",
    });
    const defaultName = `threatlens_summary_report_${new Date().toISOString().slice(0, 10)}.pdf`;
    triggerDownload(response.data, defaultName, response.headers["content-disposition"]);
  },

  downloadReportPdf: async (threatId: string, threatName?: string): Promise<void> => {
    const response = await axiosInstance.get(`/threats/${threatId}/report/pdf`, {
      responseType: "blob",
    });
    const defaultName = `threatlens_report_${threatId.slice(0, 8)}_${threatName || "scan"}.pdf`;
    triggerDownload(response.data, defaultName, response.headers["content-disposition"]);
  },
};
