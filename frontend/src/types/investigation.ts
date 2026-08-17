export type InvestigationType =
  | "username"
  | "email"
  | "domain"
  | "ip_address"
  | "dns"
  | "url"
  | "phone"
  | "metadata"
  | "reverse_image"
  | "file"
  | "breach"
  | "threat_intelligence"
  | "social_media"
  | "risk_assessment"
  | "malware";

export type InvestigationStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "partial";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type ModuleResultStatus =
  | "success"
  | "found"
  | "not_found"
  | "partial"
  | "unable_to_verify"
  | "no_data"
  | "rate_limited"
  | "failed"
  | "skipped";

export interface InvestigationResult {
  id: string;
  source: string;
  status: ModuleResultStatus;
  data: Record<string, unknown> | null;
  latency_ms: number | null;
  error_message: string | null;
  created_at: string;
}

export interface Investigation {
  id: string;
  investigation_type: InvestigationType;
  target: string;
  status: InvestigationStatus;
  risk_score: number | null;
  risk_level: RiskLevel | null;
  summary: string | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
  results: InvestigationResult[];
}

export interface InvestigationSummary {
  id: string;
  investigation_type: InvestigationType;
  target: string;
  status: InvestigationStatus;
  risk_level: RiskLevel | null;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}
