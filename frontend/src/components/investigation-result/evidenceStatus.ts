import type { ModuleResultStatus } from "@/types/investigation";

/**
 * One place defining what each evidence status means - and does not
 * mean. Per ACCOUNT3_PARTC_DESIGN.md section 5: NOT_FOUND is not SAFE,
 * SKIPPED and FAILED are not "no finding", and none of these should
 * ever be visually indistinguishable from a genuine clean result.
 */

export interface EvidenceStatusMeta {
  label: string;
  /** Short, honest, human-readable reason shown in the card's primary (collapsed) view. */
  defaultReason: string;
  badgeClassName: string;
  /** Whether a "Retry" action makes sense for this status. */
  retryable: boolean;
}

export const EVIDENCE_STATUS_META: Record<ModuleResultStatus, EvidenceStatusMeta> = {
  success: {
    label: "Success",
    defaultReason: "This source returned data.",
    badgeClassName:
      "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
    retryable: false,
  },
  not_found: {
    label: "Not Found",
    defaultReason:
      "This source ran and did not find the target. This does not confirm the target is safe elsewhere.",
    badgeClassName:
      "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    retryable: false,
  },
  skipped: {
    label: "Skipped",
    defaultReason:
      "This source did not run for this investigation. Nothing was checked here - this is not a finding.",
    badgeClassName:
      "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
    retryable: false,
  },
  failed: {
    label: "Failed",
    defaultReason:
      "This source ran but encountered an error. Whether the target has findings here is unknown.",
    badgeClassName:
      "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
    retryable: true,
  },
  rate_limited: {
    label: "Rate Limited",
    defaultReason:
      "This source was rate-limited before it could complete. Try again shortly.",
    badgeClassName:
      "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
    retryable: true,
  },
};

export function getEvidenceStatusMeta(status: ModuleResultStatus): EvidenceStatusMeta {
  return EVIDENCE_STATUS_META[status];
}
