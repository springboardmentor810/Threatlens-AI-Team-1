/**
 * Translators between the backend's payloads and the frontend's view types.
 *
 * The backend speaks snake_case and models a *detection* (see
 * ThreatLogResponse in backend/app/modules/threat_monitoring/schemas.py),
 * while the UI types were written against fixtures. Keeping the conversion in
 * one place means the pages and Redux slices did not have to change when the
 * API modules stopped returning fixtures.
 *
 * The alerts API is the exception: AlertOut is already camelCase and matches
 * the Alert interface field for field, so it needs no mapper.
 */

import { Severity, Threat } from "@/types/threat.types";
import { UploadedFile } from "@/types/upload.types";
import { Report } from "@/types/report.types";
import { RecentScan } from "@/types/dashboard.types";

/** Detection record as returned by /api/v1/threats. */
export interface ThreatLogResponse {
  id: string;
  filename: string;
  file_hash_md5?: string | null;
  file_hash_sha256?: string | null;
  file_size?: number | null;
  file_type?: string | null;
  prediction: string;
  confidence: number;
  detection_engine?: string | null;
  risk_score: number;
  risk_level: string;
  status: string;
  yara_matches?: string[] | null;
  suspicious_indicators?: Record<string, unknown> | null;
  static_analysis_results?: Record<string, unknown> | null;
  description?: string | null;
  recommended_action?: string | null;
  detected_at?: string | null;
  created_at?: string | null;
}

export function formatBytes(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

/**
 * The monitoring module's five risk levels onto the UI's Severity scale.
 * Its "minimal" has no Severity equivalent, so it maps to "info".
 * See backend/app/modules/threat_monitoring/risk_score.py.
 */
export function riskLevelToSeverity(riskLevel?: string | null): Severity {
  switch ((riskLevel ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

/** The same scale onto the Badge vocabulary, where "safe" replaces "info". */
export type BadgeRisk = NonNullable<UploadedFile["riskLevel"]>;

export function isUnscanned(prediction?: string | null): boolean {
  return (prediction ?? "").trim().toLowerCase() === "unscanned";
}

export function riskLevelToBadge(
  riskLevel?: string | null,
  prediction?: string | null
): BadgeRisk {
  // Checked before the benign case: an unscored file is not a safe one.
  if (isUnscanned(prediction)) return "unscanned";
  if (isBenign(prediction)) return "safe";
  const severity = riskLevelToSeverity(riskLevel);
  return severity === "info" ? "safe" : severity;
}

export function isBenign(prediction?: string | null): boolean {
  return ["benign", "clean", "safe", "not malicious"].includes(
    (prediction ?? "").trim().toLowerCase()
  );
}

/** Backend ThreatStatus onto the four the UI renders. */
function mapStatus(status?: string | null): Threat["status"] {
  switch ((status ?? "").toLowerCase()) {
    case "quarantined":
      return "quarantined";
    case "resolved":
    case "false_positive":
      return "resolved";
    case "monitoring":
    case "under_investigation":
      return "monitoring";
    default:
      return "monitoring";
  }
}

function detectedAt(t: ThreatLogResponse): string {
  return t.detected_at ?? t.created_at ?? new Date().toISOString();
}

/** Real signals from the scan, in place of invented "detection insights". */
function buildEvidence(t: ThreatLogResponse): string[] {
  const evidence: string[] = [];

  const yara = t.yara_matches ?? [];
  if (yara.length) {
    evidence.push(`Matched YARA rule${yara.length > 1 ? "s" : ""}: ${yara.join(", ")}`);
  }

  const indicators = (t.suspicious_indicators ?? {}) as {
    urls?: string[];
    ip_addresses?: string[];
  };
  if (indicators.urls?.length) {
    evidence.push(
      `${indicators.urls.length} embedded URL${indicators.urls.length > 1 ? "s" : ""}: ` +
        indicators.urls.slice(0, 3).join(", ")
    );
  }
  if (indicators.ip_addresses?.length) {
    evidence.push(
      `${indicators.ip_addresses.length} embedded IP address${
        indicators.ip_addresses.length > 1 ? "es" : ""
      }: ` + indicators.ip_addresses.slice(0, 3).join(", ")
    );
  }

  const pe = (t.static_analysis_results ?? {}) as { analysis?: { pe_file?: string } };
  if (pe.analysis?.pe_file === "Yes") {
    evidence.push("Parsed as a Portable Executable; EMBER features extracted");
  }

  if (t.detection_engine) {
    evidence.push(`Scored by ${t.detection_engine}`);
  }

  return evidence;
}

export function toThreat(t: ThreatLogResponse): Threat {
  const yara = t.yara_matches ?? [];
  const staticResults = (t.static_analysis_results ?? {}) as {
    ai_analysis?: {
      available?: boolean;
      status?: string;
      reason?: string;
      model?: string;
      verdict?: string;
      malware_probability?: number;
      risk_score?: number;
      risk_level?: string;
    };
  };
  const ai = staticResults.ai_analysis;
  const isAiExecuted = ai?.available === true;
  const isAiNotApplicable =
    ai?.available === false &&
    (ai.status === "Not Applicable" || (ai.reason && ai.reason.toLowerCase().includes("not a pe")));
  const isAiFailed = ai?.available === false && !isAiNotApplicable;

  let aiStatus: "executed" | "not_applicable" | "failed" = "not_applicable";
  if (isAiExecuted) {
    aiStatus = "executed";
  } else if (isAiFailed) {
    aiStatus = "failed";
  } else if (isAiNotApplicable) {
    aiStatus = "not_applicable";
  } else if (t.file_type && ["exe", "dll"].includes(t.file_type.toLowerCase())) {
    aiStatus = "executed";
  }

  return {
    id: String(t.id),
    threatName: t.prediction,
    threatFamily: isBenign(t.prediction) || isUnscanned(t.prediction) ? "—" : t.prediction,
    threatScore: t.risk_score,
    severity: riskLevelToSeverity(t.risk_level),
    detectionTime: detectedAt(t),
    sha256: t.file_hash_sha256 ?? "",
    md5: t.file_hash_md5 ?? "",
    fileSize: formatBytes(t.file_size),
    detectionEngine: t.detection_engine ?? "ThreatLens AI",
    yaraRule: yara.length ? yara.join(", ") : "—",
    description:
      t.description ?? `${t.prediction} detected at ${t.confidence}% malware probability.`,
    recommendedAction: t.recommended_action ?? "Review the detection details.",
    // The timeline has its own endpoint (/api/v1/threats/timeline/{id});
    // threatApi.getThreatById fills this in.
    timeline: [],
    status: mapStatus(t.status),
    malwareProbability: t.confidence,
    riskLevel: t.risk_level,
    aiStatus,
    aiReason: ai?.reason,
    aiModel: ai?.model,
    aiMalwareProbability: ai?.malware_probability,
    aiRiskScore: ai?.risk_score,
    aiRiskLevel: ai?.risk_level,
    aiVerdict: ai?.verdict,
    evidence: buildEvidence(t),
  };
}

export function toUploadedFile(t: ThreatLogResponse): UploadedFile {
  return {
    id: String(t.id),
    name: t.filename,
    size: formatBytes(t.file_size),
    type: t.file_type ?? "application/octet-stream",
    progress: 100,
    status: "completed",
    riskLevel: riskLevelToBadge(t.risk_level, t.prediction),
    sha256: t.file_hash_sha256 ?? undefined,
    md5: t.file_hash_md5 ?? undefined,
    uploadedAt: detectedAt(t),
  };
}

export function toReport(t: ThreatLogResponse): Report {
  return {
    id: String(t.id),
    fileName: t.filename,
    scanDate: detectedAt(t),
    riskLevel: riskLevelToBadge(t.risk_level, t.prediction),
    threatFamily: isBenign(t.prediction) || isUnscanned(t.prediction) ? null : t.prediction,
    fileSize: formatBytes(t.file_size),
    status: "completed",
    analyst: t.detection_engine ?? "ThreatLens AI",
  };
}

export function toRecentScan(t: ThreatLogResponse): RecentScan {
  return {
    id: String(t.id),
    fileName: t.filename,
    riskLevel: riskLevelToBadge(t.risk_level, t.prediction),
    time: detectedAt(t),
  };
}
