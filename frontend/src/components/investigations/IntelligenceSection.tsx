import { useState } from "react";
import type { Investigation } from "@/types/investigation";
import { Card } from "@/components/Card";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { formatRiskScore } from "@/utils/formatters";
import { IPIntelligenceRenderer } from "@/components/investigations/IPIntelligenceRenderer";

/**
 * Dispatches to a dedicated, structured renderer per investigation
 * type when one exists. Every type without a dedicated renderer falls
 * through to GenericIntelligenceView below, which is a byte-for-byte
 * extraction of what InvestigationDetailPage rendered before this
 * change - so nothing about any other investigation type's page
 * changes as a result of adding the IP renderer.
 */
export function IntelligenceSection({ investigation }: { investigation: Investigation }) {
  if (investigation.investigation_type === "ip_address") {
    return <IPIntelligenceRenderer investigation={investigation} />;
  }

  return <GenericIntelligenceView investigation={investigation} />;
}

function GenericIntelligenceView({ investigation }: { investigation: Investigation }) {
  const [expandedResult, setExpandedResult] = useState<string | null>(null);

  return (
    <>
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
        <Card>
          <p className="text-sm text-slate-500 dark:text-slate-400">Status</p>
          <div className="mt-2">
            <StatusBadge status={investigation.status} />
          </div>
        </Card>
        <Card>
          <p className="text-sm text-slate-500 dark:text-slate-400">Risk Level</p>
          <div className="mt-2">
            <RiskBadge level={investigation.risk_level} />
          </div>
        </Card>
        <Card>
          <p className="text-sm text-slate-500 dark:text-slate-400">Risk Score</p>
          <p className="mt-2 text-lg font-semibold text-slate-900 dark:text-white">
            {formatRiskScore(investigation.risk_score)}
          </p>
        </Card>
      </div>

      {investigation.summary && (
        <Card>
          <h2 className="mb-2 font-semibold text-slate-900 dark:text-white">
            Summary
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            {investigation.summary}
          </p>
        </Card>
      )}

      <div>
        <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
          Evidence ({investigation.results.length} source
          {investigation.results.length === 1 ? "" : "s"})
        </h2>

        {investigation.results.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              No evidence sources recorded for this investigation.
            </p>
          </Card>
        ) : (
          <div className="space-y-3">
            {investigation.results.map((result) => (
              <Card key={result.id}>
                <button
                  onClick={() =>
                    setExpandedResult(
                      expandedResult === result.id ? null : result.id
                    )
                  }
                  className="flex w-full items-center justify-between text-left"
                >
                  <div className="flex items-center gap-3">
                    <span className="font-medium capitalize text-slate-900 dark:text-white">
                      {result.source.replace(/_/g, " ")}
                    </span>
                    <StatusBadge status={result.status} />
                  </div>
                  {result.latency_ms !== null && (
                    <span className="text-xs text-slate-400">
                      {result.latency_ms}ms
                    </span>
                  )}
                </button>

                {expandedResult === result.id && (
                  <pre className="mt-3 max-h-80 overflow-auto rounded-lg bg-slate-50 p-3 text-xs text-slate-700 dark:bg-slate-900 dark:text-slate-300">
                    {result.error_message
                      ? result.error_message
                      : JSON.stringify(result.data, null, 2)}
                  </pre>
                )}
              </Card>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
