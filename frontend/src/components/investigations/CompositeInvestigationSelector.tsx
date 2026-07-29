import { useEffect, useState } from "react";
import { Search } from "lucide-react";
import clsx from "clsx";

import { useInvestigations } from "@/hooks/useInvestigations";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { EmptyState, ErrorState } from "@/components/StateViews";
import { TableSkeleton } from "@/components/LoadingSkeleton";
import { truncate } from "@/utils/formatters";
import type { InvestigationSummary } from "@/types/investigation";

const MIN_SELECTIONS = 2;
const MAX_SELECTIONS = 20;
const SEARCH_DEBOUNCE_MS = 300;

interface CompositeInvestigationSelectorProps {
  selected: Map<string, InvestigationSummary>;
  onChange: (next: Map<string, InvestigationSummary>) => void;
  disabled?: boolean;
}

export function CompositeInvestigationSelector({
  selected,
  onChange,
  disabled,
}: CompositeInvestigationSelectorProps) {
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query]);

  const { data, isLoading, isError, refetch } = useInvestigations({
    page: 1,
    page_size: 25,
    query: debouncedQuery || undefined,
  });

  function toggle(investigation: InvestigationSummary) {
    if (disabled) return;

    const next = new Map(selected);

    if (next.has(investigation.id)) {
      next.delete(investigation.id);
    } else {
      if (next.size >= MAX_SELECTIONS) return;
      next.set(investigation.id, investigation);
    }

    onChange(next);
  }

  return (
    <div className="space-y-3">
      <div>
        <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
          Select Investigations
        </label>

        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search existing investigations..."
            aria-label="Search existing investigations"
            disabled={disabled}
            className="w-full rounded-lg border border-slate-300 py-2 pl-9 pr-3 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          />
        </div>
      </div>

      <div className="max-h-56 overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-700">
        {isLoading ? (
          <div className="p-3">
            <TableSkeleton rows={4} />
          </div>
        ) : isError ? (
          <div className="p-3">
            <ErrorState
              message="Couldn't load your investigations."
              onRetry={() => refetch()}
            />
          </div>
        ) : !data?.items.length ? (
          <div className="p-3">
            <EmptyState
              title="No investigations found"
              description={
                query
                  ? "Try a different search term."
                  : "Start and complete an investigation first, then combine it here."
              }
            />
          </div>
        ) : (
          <ul role="listbox" aria-multiselectable="true" className="divide-y divide-slate-100 dark:divide-slate-800">
            {data.items.map((investigation) => {
              const isChecked = selected.has(investigation.id);
              const isDisabledOption =
                disabled ||
                (!isChecked && selected.size >= MAX_SELECTIONS);

              return (
                <li key={investigation.id}>
                  <label
                    className={clsx(
                      "flex cursor-pointer items-start gap-3 px-3 py-2.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-800/60",
                      isDisabledOption && "cursor-not-allowed opacity-50"
                    )}
                  >
                    <input
                      type="checkbox"
                      role="option"
                      aria-selected={isChecked}
                      checked={isChecked}
                      disabled={isDisabledOption}
                      onChange={() => toggle(investigation)}
                      className="mt-0.5 h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                    />
                    <span className="min-w-0">
                      <span className="block truncate font-medium text-slate-800 dark:text-slate-200">
                        {truncate(investigation.target, 48)}
                      </span>
                      <span className="mt-0.5 flex items-center gap-2 text-xs capitalize text-slate-500 dark:text-slate-400">
                        {investigation.investigation_type.replace(/_/g, " ")}
                        <StatusBadge status={investigation.status} />
                        <RiskBadge level={investigation.risk_level} />
                      </span>
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
        <span>
          Selected: <span className="font-medium">{selected.size}</span> investigation
          {selected.size === 1 ? "" : "s"}
        </span>
        {selected.size < MIN_SELECTIONS && (
          <span>Select at least {MIN_SELECTIONS} to continue.</span>
        )}
      </div>
    </div>
  );
}
