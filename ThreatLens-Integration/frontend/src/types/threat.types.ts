export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Threat {
  id: string;
  threatName: string;
  threatFamily: string;
  threatScore: number;
  severity: Severity;
  detectionTime: string;
  sha256: string;
  md5: string;
  fileSize: string;
  detectionEngine: string;
  yaraRule: string;
  description: string;
  recommendedAction: string;
  timeline: { time: string; event: string }[];
  status: "quarantined" | "removed" | "monitoring" | "resolved";

  /**
   * Likelihood the file is malware, 0-100, as recorded by the detection.
   *
   * Named for what it is. It was "confidence", which invited the UI to label
   * it "AI confidence" - a different quantity, and one the backend no longer
   * returns at all because its old value was inverted for benign verdicts.
   */
  malwareProbability: number;
  /** The monitoring module's risk level, e.g. "critical" or "minimal". */
  riskLevel: string;

  /**
   * The AI module is consumed as a prediction service. These are the only
   * fields it surfaces; per-model probabilities, ensemble weights, tuning
   * parameters and the feature vector stay server-side.
   */
  aiStatus?: "executed" | "not_applicable" | "failed";
  aiReason?: string;
  aiModel?: string;
  aiVerdict?: string;
  /** 0-1 as the model reports it; the UI renders it as a percentage. */
  aiMalwareProbability?: number;
  aiRiskScore?: number;
  aiRiskLevel?: string;
  /**
   * Concrete signals from static analysis - YARA hits, embedded URLs and IPs,
   * whether the file parsed as a PE. Replaces a hardcoded list of invented
   * "detection insights"; an empty array means nothing notable was found,
   * which is itself a finding.
   */
  evidence: string[];
}
