import type { InvestigationResult } from "@/types/investigation";
import { formatDate } from "@/utils/formatters";

interface TechnicalDetailsProps {
  result: InvestigationResult;
}

/**
 * Everything that shouldn't dominate an analyst's first read of a
 * result: exact latency, raw provider payload, and timestamps. Used
 * both standalone (generic EvidenceCard) and embedded inside the
 * dedicated module renderers so nothing is ever hidden - just moved
 * out of the primary view.
 */
export function TechnicalDetails({ result }: TechnicalDetailsProps) {
  return (
    <div className="space-y-3 text-sm">
      <dl className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
        <div className="flex justify-between gap-2 sm:block">
          <dt className="text-xs uppercase tracking-wide text-slate-400">
            Latency
          </dt>
          <dd className="text-slate-700 dark:text-slate-300">
            {result.latency_ms !== null ? `${result.latency_ms}ms` : "—"}
          </dd>
        </div>
        <div className="flex justify-between gap-2 sm:block">
          <dt className="text-xs uppercase tracking-wide text-slate-400">
            Recorded
          </dt>
          <dd className="text-slate-700 dark:text-slate-300">
            {formatDate(result.created_at)}
          </dd>
        </div>
      </dl>

      {result.error_message && (
        <div>
          <p className="text-xs uppercase tracking-wide text-slate-400">
            Provider error
          </p>
          <p className="mt-1 whitespace-pre-wrap break-words text-slate-700 dark:text-slate-300">
            {result.error_message}
          </p>
        </div>
      )}

      <div>
        <p className="mb-1 text-xs uppercase tracking-wide text-slate-400">
          Raw data
        </p>
        {result.data && Object.keys(result.data).length > 0 ? (
          <pre className="max-h-80 overflow-auto rounded-lg bg-slate-50 p-3 text-xs text-slate-700 dark:bg-slate-900 dark:text-slate-300">
            {JSON.stringify(result.data, null, 2)}
          </pre>
        ) : (
          <p className="text-slate-500 dark:text-slate-400">
            No data returned by this source.
          </p>
        )}
      </div>
    </div>
  );
}
