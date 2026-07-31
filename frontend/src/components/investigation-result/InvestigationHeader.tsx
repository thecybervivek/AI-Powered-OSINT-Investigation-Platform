import { FileText, Loader2, AlertTriangle, Clock } from "lucide-react";

import { Button } from "@/components/Button";
import { StatusBadge } from "@/components/Badge";
import { formatDate } from "@/utils/formatters";
import type { Investigation } from "@/types/investigation";

interface InvestigationHeaderProps {
  investigation: Investigation;
  onGenerateReport: () => void;
  isGeneratingReport: boolean;
}

export function InvestigationHeader({
  investigation,
  onGenerateReport,
  isGeneratingReport,
}: InvestigationHeaderProps) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="break-all text-2xl font-semibold text-slate-900 dark:text-white">
            {investigation.target}
          </h1>
          <p className="mt-1 text-sm capitalize text-slate-500 dark:text-slate-400">
            {investigation.investigation_type.replace(/_/g, " ")} investigation
            {" · "}
            {investigation.started_at
              ? `Started ${formatDate(investigation.started_at)}`
              : `Created ${formatDate(investigation.created_at)}`}
            {investigation.completed_at &&
              ` · Completed ${formatDate(investigation.completed_at)}`}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <StatusBadge status={investigation.status} />
          <Button onClick={onGenerateReport} isLoading={isGeneratingReport}>
            <FileText className="h-4 w-4" />
            Generate Report
          </Button>
        </div>
      </div>

      <StatusNotice investigation={investigation} />
    </div>
  );
}

/**
 * Honest, non-fabricated messaging for non-terminal or degraded
 * states. No percentages, no fake step-by-step progress - only what
 * the backend actually tells us via `status`/`error_message`.
 */
function StatusNotice({ investigation }: { investigation: Investigation }) {
  if (investigation.status === "queued") {
    return (
      <Notice icon={<Clock className="h-4 w-4" />} tone="neutral">
        Queued - this investigation hasn't started collecting evidence yet.
      </Notice>
    );
  }

  if (investigation.status === "running") {
    return (
      <Notice icon={<Loader2 className="h-4 w-4 animate-spin" />} tone="info">
        In progress - evidence will appear below as each source completes.
        This page updates automatically.
      </Notice>
    );
  }

  if (investigation.status === "partial") {
    return (
      <Notice icon={<AlertTriangle className="h-4 w-4" />} tone="warning">
        Completed with partial results - one or more sources did not finish.
        Review the evidence statuses below; a source marked Failed or
        Skipped was not successfully checked, not cleared.
      </Notice>
    );
  }

  if (investigation.status === "failed") {
    return (
      <Notice icon={<AlertTriangle className="h-4 w-4" />} tone="error">
        {investigation.error_message?.trim()
          ? investigation.error_message
          : "This investigation failed before evidence could be collected."}
      </Notice>
    );
  }

  return null;
}

type NoticeTone = "neutral" | "info" | "warning" | "error";

function Notice({
  icon,
  tone,
  children,
}: {
  icon: React.ReactNode;
  tone: NoticeTone;
  children: React.ReactNode;
}) {
  const toneClasses: Record<NoticeTone, string> = {
    neutral:
      "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300",
    info: "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900/50 dark:bg-blue-950/20 dark:text-blue-300",
    warning:
      "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/50 dark:bg-orange-950/20 dark:text-orange-300",
    error:
      "border-red-200 bg-red-50 text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300",
  };

  return (
    <div
      role="status"
      className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-sm ${toneClasses[tone]}`}
    >
      <span className="mt-0.5 shrink-0">{icon}</span>
      <span>{children}</span>
    </div>
  );
}
