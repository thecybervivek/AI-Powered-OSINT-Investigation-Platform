import type { RiskLevel } from "./investigation";

export type ReportStatus = "generating" | "completed" | "failed";
export type AIEngineUsed = "openai" | "local_deterministic";

export interface IOC {
  type: string;
  value: string;
  risk_level: RiskLevel | null;
  risk_score: number | null;
  investigation_id: string;
}

export interface TimelineEvent {
  timestamp: string;
  event: string;
  investigation_id: string;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  evidence_sources: string[];
}

export interface EvidenceCorrelation {
  finding: string;
  related_sources: string[];
}

export interface Report {
  id: string;
  title: string;
  investigation_ids: string[];
  status: ReportStatus;
  executive_summary: string | null;
  technical_summary: string | null;
  investigation_summary: string | null;
  threat_analysis: string | null;
  risk_explanation: string | null;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  indicators_of_compromise: IOC[] | null;
  evidence_timeline: TimelineEvent[] | null;
  evidence_correlation: EvidenceCorrelation[] | null;
  ai_recommendations: string[] | null;
  mitre_attack_mapping: MitreTechnique[] | null;
  investigation_metadata: Record<string, unknown> | null;
  ai_engine_used: AIEngineUsed | null;
  confidence_score: number | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

export interface ReportSummary {
  id: string;
  title: string;
  status: ReportStatus;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  ai_engine_used: AIEngineUsed | null;
  created_at: string;
}
