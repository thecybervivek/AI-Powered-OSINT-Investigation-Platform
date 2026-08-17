import type { InvestigationResult, ModuleResultStatus } from "@/types/investigation";
import { EvidenceCard } from "./EvidenceCard";

interface EvidenceListProps {
  results: InvestigationResult[];
  /** Source names already rendered by a dedicated module summary above this list - still shown here (nothing is hidden), just not called out as duplicated content. */
  title?: string;
}

// Ordering only - never a value judgment. SUCCESS surfaces first since
// it's the most likely to hold immediately-actionable findings; this is
// not a claim that FAILED/SKIPPED sources are less important.
const STATUS_ORDER: ModuleResultStatus[] = [
  "success",
  "found",
  "not_found",
  "no_data",
  "partial",
  "unable_to_verify",
  "rate_limited",
  "failed",
  "skipped",
];

export function EvidenceList({ results, title = "Evidence" }: EvidenceListProps) {
  const sorted = [...results].sort(
    (a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status)
  );

  return (
    <div>
      <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
        {title} ({results.length} source{results.length === 1 ? "" : "s"})
      </h2>

      {results.length === 0 ? (
        <div className="rounded-lg border border-slate-200 p-4 text-sm text-slate-500 dark:border-slate-700 dark:text-slate-400">
          No evidence sources recorded for this investigation.
        </div>
      ) : (
        <div className="space-y-3">
          {sorted.map((result) => (
            <EvidenceCard key={result.id} result={result} />
          ))}
        </div>
      )}
    </div>
  );
}
