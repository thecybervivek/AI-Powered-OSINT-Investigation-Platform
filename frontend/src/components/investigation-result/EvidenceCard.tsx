import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import clsx from "clsx";

import type { InvestigationResult } from "@/types/investigation";
import { getEvidenceStatusMeta } from "./evidenceStatus";
import { TechnicalDetails } from "./TechnicalDetails";

interface EvidenceCardProps {
  result: InvestigationResult;
  /** Renders open by default - used when a dedicated module renderer has already summarized this source and just wants raw access available. */
  defaultExpanded?: boolean;
}

/**
 * Some sources encode which resolved IP they ran against directly in
 * the source name (e.g. "asn_lookup:93.184.216.34" from the Domain
 * Investigation pipeline, which fans IP-dependent lookups out across
 * every resolved public IP). Split that out into a readable label
 * rather than showing the raw colon-joined string.
 */
function formatSourceName(source: string): string {
  const [base, suffix] = source.split(":");
  const label = base.replace(/_/g, " ");
  return suffix ? `${label} (${suffix})` : label;
}

export function EvidenceCard({ result, defaultExpanded = false }: EvidenceCardProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const meta = getEvidenceStatusMeta(result.status);

  const reason = result.error_message?.trim() || meta.defaultReason;

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700">
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        aria-expanded={expanded}
        className="flex w-full items-start justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="flex min-w-0 items-start gap-3">
          {expanded ? (
            <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
          ) : (
            <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
          )}

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium capitalize text-slate-900 dark:text-white">
                {formatSourceName(result.source)}
              </span>
              <span
                className={clsx(
                  "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
                  meta.badgeClassName
                )}
              >
                {meta.label}
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {reason}
            </p>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-slate-100 px-4 py-3 dark:border-slate-800">
          <TechnicalDetails result={result} />
        </div>
      )}
    </div>
  );
}
