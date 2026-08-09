import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Globe, HelpCircle, MapPin, Server, ShieldAlert } from "lucide-react";
import type { Investigation, InvestigationResult } from "@/types/investigation";
import { Card } from "@/components/Card";

// ==========================================================
// Data access helpers
// ==========================================================
// IP investigations always persist these individual result rows
// (backend/app/services/ip_service.py), independent of the newer
// "grouped_view"/"threat_assessment" rows added alongside this
// renderer - reading directly from them means an IP investigation run
// before this change (which has every row except reverse_dns/
// greynoise/otx/threat_assessment/grouped_view) still renders
// sensibly instead of breaking.

function findResult(
  investigation: Investigation,
  source: string
): InvestigationResult | null {
  return investigation.results.find((r) => r.source === source) ?? null;
}

function isUnavailable(result: InvestigationResult | null): boolean {
  return result === null || result.status === "skipped";
}

function summaryOf(result: InvestigationResult | null): string | null {
  if (!result || !result.data) return null;
  const summary = result.data["summary"];
  return typeof summary === "string" ? summary : null;
}

// ==========================================================
// Threat Assessment
// ==========================================================

type AssessmentKind =
  | "malicious_detected"
  | "suspicious_detected"
  | "no_malicious_evidence"
  | "incomplete"
  | "insufficient_evidence";

const ASSESSMENT_DISPLAY: Record<
  AssessmentKind,
  { label: string; tone: string; icon: typeof AlertTriangle }
> = {
  malicious_detected: {
    label: "Malicious indicators detected",
    tone: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
    icon: ShieldAlert,
  },
  suspicious_detected: {
    label: "Suspicious indicators detected",
    tone: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
    icon: AlertTriangle,
  },
  no_malicious_evidence: {
    label: "No malicious evidence detected",
    tone: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
    icon: CheckCircle2,
  },
  incomplete: {
    label: "Threat assessment incomplete",
    tone: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    icon: HelpCircle,
  },
  insufficient_evidence: {
    label: "Insufficient evidence",
    tone: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    icon: HelpCircle,
  },
};

function ThreatAssessmentCard({ investigation }: { investigation: Investigation }) {
  const result = findResult(investigation, "threat_assessment");
  const assessment = result?.data?.["assessment"] as AssessmentKind | undefined;
  const display = assessment ? ASSESSMENT_DISPLAY[assessment] : null;
  const Icon = display?.icon ?? HelpCircle;

  return (
    <Card>
      <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
        Assessment
      </h2>

      <div className="flex items-center gap-3">
        <span
          className={
            "flex h-9 w-9 items-center justify-center rounded-lg " +
            (display?.tone ?? "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300")
          }
        >
          <Icon className="h-5 w-5" />
        </span>
        <p className="font-medium text-slate-900 dark:text-white">
          {display?.label ?? "Insufficient evidence"}
        </p>
      </div>

      {investigation.summary && (
        <p className="mt-3 text-sm text-slate-600 dark:text-slate-400">
          {investigation.summary}
        </p>
      )}
    </Card>
  );
}

// ==========================================================
// Network group: ASN / Geolocation / Reverse DNS
// ==========================================================

function NetworkSection({ investigation }: { investigation: Investigation }) {
  const asn = findResult(investigation, "asn_lookup");
  const geo = findResult(investigation, "ip_geolocation");
  const reverseDns = findResult(investigation, "reverse_dns");

  return (
    <Card>
      <h2 className="mb-4 font-semibold text-slate-900 dark:text-white">Network</h2>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <NetworkField
          icon={<Server className="h-4 w-4" />}
          label="ASN"
          result={asn}
          fallback="ASN lookup temporarily unavailable."
        />
        <NetworkField
          icon={<MapPin className="h-4 w-4" />}
          label="Geolocation"
          result={geo}
          fallback="Location could not be determined."
        />
        <NetworkField
          icon={<Globe className="h-4 w-4" />}
          label="Reverse DNS"
          result={reverseDns}
          fallback="Reverse DNS lookup was not performed."
        />
      </div>
    </Card>
  );
}

function NetworkField({
  icon,
  label,
  result,
  fallback,
}: {
  icon: ReactNode;
  label: string;
  result: InvestigationResult | null;
  fallback: string;
}) {
  const text = summaryOf(result) ?? (result?.error_message ?? fallback);

  return (
    <div>
      <div className="mb-1 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {icon}
        {label}
      </div>
      <p className="text-sm text-slate-800 dark:text-slate-200">{text}</p>
    </div>
  );
}

// ==========================================================
// Reputation Providers
// ==========================================================

const REPUTATION_SOURCES: { source: string; label: string }[] = [
  { source: "abuseipdb", label: "AbuseIPDB" },
  { source: "virustotal_ip", label: "VirusTotal" },
  { source: "greynoise", label: "GreyNoise" },
  { source: "otx", label: "OTX" },
];

function ReputationSection({ investigation }: { investigation: Investigation }) {
  const rows = REPUTATION_SOURCES.map(({ source, label }) => ({
    label,
    result: findResult(investigation, source),
  })).filter((row) => row.result !== null); // provider never even attempted in this investigation - omit rather than show a false "Unavailable"

  if (rows.length === 0) {
    return null;
  }

  return (
    <Card>
      <h2 className="mb-4 font-semibold text-slate-900 dark:text-white">
        Reputation Providers
      </h2>

      <ul className="space-y-3">
        {rows.map(({ label, result }) => (
          <li key={label} className="flex items-start justify-between gap-4">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {label}
            </span>
            <span
              className={
                "text-right text-sm " +
                (isUnavailable(result)
                  ? "text-slate-400 dark:text-slate-500"
                  : "text-slate-700 dark:text-slate-300")
              }
            >
              {isUnavailable(result) ? "Unavailable" : summaryOf(result) ?? "No summary available."}
            </span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

// ==========================================================
// Top-level renderer
// ==========================================================

export function IPIntelligenceRenderer({ investigation }: { investigation: Investigation }) {
  return (
    <div className="space-y-6">
      <ThreatAssessmentCard investigation={investigation} />
      <NetworkSection investigation={investigation} />
      <ReputationSection investigation={investigation} />
    </div>
  );
}
