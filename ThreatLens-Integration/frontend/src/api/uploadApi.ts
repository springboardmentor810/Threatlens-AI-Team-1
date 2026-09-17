import { AiAnalysis, UploadedFile } from "@/types/upload.types";
import axiosInstance from "./axiosInstance";
import {
  ThreatLogResponse,
  formatBytes,
  riskLevelToBadge,
  toUploadedFile,
} from "./mappers";

interface PaginatedThreats {
  items: ThreatLogResponse[];
  total: number;
}

export interface UploadResult extends UploadedFile {
  aiAnalysis: AiAnalysis;
  yaraMatches: string[];
  reportUrl: string;
}

export const uploadApi = {
  /** Scan history is the detection log: every scored upload is recorded. */
  getHistory: async (): Promise<UploadedFile[]> => {
    const { data } = await axiosInstance.get<PaginatedThreats>("/threats", {
      params: { page: 1, page_size: 50 },
    });
    return data.items.map(toUploadedFile);
  },

  uploadFile: async (
    file: File,
    onProgress: (pct: number) => void
  ): Promise<UploadResult> => {
    const form = new FormData();
    form.append("file", file);

    const { data } = await axiosInstance.post("/upload", form, {
      headers: { "Content-Type": "multipart/form-data" },
      // Static analysis plus EMBER feature extraction takes longer than the
      // client's default timeout allows.
      timeout: 120000,
      onUploadProgress: (event) => {
        if (!event.total) return;
        // Reserve the last 10% for server-side analysis, which reports no
        // progress of its own.
        onProgress(Math.round((event.loaded / event.total) * 90));
      },
    });

    onProgress(100);

    const ai: AiAnalysis = data.ai_analysis ?? { available: false };
    const detection = data.detection?.data ?? data.detection ?? null;

    return {
      id: (detection?.threat_id ?? detection?.id)
        ? String(detection.threat_id ?? detection.id)
        : data.stored_filename,
      name: data.original_filename,
      size: formatBytes(data.metadata?.size_bytes),
      type: data.file_type?.mime_type ?? file.type ?? "application/octet-stream",
      progress: 100,
      status: "completed",
      riskLevel: riskLevelToBadge(detection?.risk_level, detection?.prediction),
      sha256: data.hashes?.sha256,
      md5: data.hashes?.md5,
      uploadedAt: new Date().toISOString(),
      aiAnalysis: ai,
      yaraMatches: data.yara_results?.matched_rules ?? [],
      reportUrl: data.report_url,
    };
  },

  deleteUpload: async (id: string): Promise<void> => {
    await axiosInstance.delete(`/threats/${id}`);
  },
};
