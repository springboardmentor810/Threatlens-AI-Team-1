/**
 * The AI stage of the upload response (backend/app/api/upload.py).
 *
 * `available` is false for a non-PE file, or when EMBER or the model
 * artifacts are missing; `reason` then explains which.
 *
 * These are the only fields the AI module exposes. Per-model probabilities,
 * ensemble weights, tuning parameters and the 2,381-feature vector are
 * implementation detail and stay server-side.
 */
export interface AiAnalysis {
  available: boolean;
  reason?: string;
  verdict?: "MALWARE" | "BENIGN";
  malware_probability?: number;
  risk_score?: number;
  risk_level?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  model?: string;
}

export interface UploadedFile {
  id: string;
  name: string;
  size: string;
  type: string;
  progress: number;
  status: "queued" | "uploading" | "analyzing" | "completed" | "failed";
  riskLevel?: "critical" | "high" | "medium" | "low" | "safe" | "unscanned";
  sha256?: string;
  md5?: string;
  uploadedAt: string;
  aiAnalysis?: AiAnalysis;
  yaraMatches?: string[];
}
