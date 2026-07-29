import { useMemo, useState } from "react";
import { Search } from "lucide-react";
import clsx from "clsx";

import { EmptyState } from "@/components/StateViews";
import type { InvestigationType } from "@/types/investigation";
import {
  CATEGORY_ORDER,
  searchInvestigationTypes,
  type InvestigationTypeDefinition,
} from "./investigationTypes.config";

interface InvestigationTypeSelectorProps {
  onSelect: (type: InvestigationType) => void;
  initialQuery?: string;
}

export function InvestigationTypeSelector({
  onSelect,
  initialQuery = "",
}: InvestigationTypeSelectorProps) {
  const [query, setQuery] = useState(initialQuery);

  const grouped = useMemo(() => {
    const filtered = searchInvestigationTypes(query);

    const byCategory = new Map<string, InvestigationTypeDefinition[]>();

    for (const category of CATEGORY_ORDER) {
      byCategory.set(category, []);
    }

    for (const def of filtered) {
      byCategory.get(def.category)?.push(def);
    }

    return byCategory;
  }, [query]);

  const hasResults = Array.from(grouped.values()).some((defs) => defs.length > 0);

  return (
    <div className="space-y-5">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
        <input
          autoFocus
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search investigation types..."
          aria-label="Search investigation types"
          className="w-full rounded-lg border border-slate-300 py-2 pl-9 pr-3 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
        />
      </div>

      {!hasResults ? (
        <EmptyState
          title="No investigation types match your search"
          description="Try a different keyword, such as “domain”, “hash”, or “image”."
        />
      ) : (
        <div className="space-y-6">
          {CATEGORY_ORDER.map((category) => {
            const defs = grouped.get(category) ?? [];

            if (defs.length === 0) return null;

            return (
              <div key={category}>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  {category}
                </h3>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {defs.map((def) => (
                    <InvestigationTypeCard
                      key={def.type}
                      definition={def}
                      onSelect={onSelect}
                    />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function InvestigationTypeCard({
  definition,
  onSelect,
}: {
  definition: InvestigationTypeDefinition;
  onSelect: (type: InvestigationType) => void;
}) {
  const Icon = definition.icon;

  return (
    <button
      type="button"
      disabled={!definition.available}
      onClick={() => onSelect(definition.type)}
      aria-label={`Start a ${definition.label} investigation`}
      className={clsx(
        "flex items-start gap-3 rounded-lg border p-3 text-left text-sm transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2",
        definition.available
          ? "border-slate-200 hover:border-brand-400 hover:bg-brand-50/50 dark:border-slate-700 dark:hover:border-brand-600 dark:hover:bg-brand-900/10"
          : "cursor-not-allowed border-slate-100 opacity-60 dark:border-slate-800"
      )}
    >
      <span className="mt-0.5 rounded-md bg-slate-100 p-2 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
        <Icon className="h-4 w-4" />
      </span>

      <span className="min-w-0">
        <span className="flex items-center gap-2">
          <span className="font-medium text-slate-900 dark:text-white">
            {definition.label}
          </span>
          {!definition.available && (
            <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-500 dark:bg-slate-800 dark:text-slate-400">
              Coming soon
            </span>
          )}
        </span>
        <span className="mt-0.5 block text-xs text-slate-500 dark:text-slate-400">
          {definition.available
            ? definition.description
            : definition.unavailableReason ?? definition.description}
        </span>
      </span>
    </button>
  );
}
