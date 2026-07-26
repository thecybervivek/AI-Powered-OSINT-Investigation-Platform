import { useParams, useNavigate, Link } from "react-router-dom";
import { FileText, Loader2 } from "lucide-react";
import { useState } from "react";
import { useInvestigation } from "@/hooks/useInvestigations";
import { useGenerateReport } from "@/hooks/useReports";
import { useToast } from "@/contexts/ToastContext";
import { Card } from "@/components/Card";
import { Button } from "@/components/Button";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { CardSkeleton } from "@/components/LoadingSkeleton";
import { ErrorState } from "@/components/StateViews";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { formatDate, formatRiskScore } from "@/utils/formatters";

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const { data: investigation, isLoading, isError, refetch } = useInvestigation(id);
  const generateReport = useGenerateReport();
  const [expandedResult, setExpandedResult] = useState<string | null>(null);

  async function handleGenerateReport() {
    if (!investigation) return;

    try {
      const report = await generateReport.mutateAsync({
        investigationIds: [investigation.id],
      });
      showToast("success", "Report generated.");
      navigate(`/reports/${report.id}`);
    } catch {
      showToast("error", "Failed to generate report.");
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (isError || !investigation) {
    return <ErrorState onRetry={() => refetch()} />;
  }

  return (
    <div className="space-y-6">
      <Breadcrumbs
        items={[
          { label: "Dashboard", to: "/dashboard" },
          { label: "Investigations", to: "/investigations" },
          { label: investigation.target },
        ]}
      />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="break-all text-2xl font-semibold text-slate-900 dark:text-white">
            {investigation.target}
          </h1>
          <p className="mt-1 text-sm capitalize text-slate-500 dark:text-slate-400">
            {investigation.investigation_type.replace("_", " ")} investigation ·
            Started {formatDate(investigation.started_at)}
          </p>
        </div>
        <Button
          onClick={handleGenerateReport}
          isLoading={generateReport.isPending}
        >
          <FileText className="h-4 w-4" />
          Generate Report
        </Button>
      </div>

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

      {generateReport.isPending && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          Generating AI-correlated report…
        </div>
      )}

      <Link to="/investigations" className="inline-block text-sm text-brand-600 hover:underline">
        ← Back to Investigations
      </Link>
    </div>
  );
}
