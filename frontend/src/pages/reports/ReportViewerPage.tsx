import { useState } from "react";
import { useParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import { Download } from "lucide-react";

import { useReport } from "@/hooks/useReports";
import { reportService } from "@/services/reportService";
import { Card } from "@/components/Card";
import { Button } from "@/components/Button";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { CardSkeleton } from "@/components/LoadingSkeleton";
import { ErrorState } from "@/components/StateViews";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { formatDate, formatRiskScore } from "@/utils/formatters";

export function ReportViewerPage() {
  const { id } = useParams<{ id: string }>();
  const { data: report, isLoading, isError, refetch } = useReport(id);

  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <CardSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  if (isError || !report) {
    return <ErrorState onRetry={() => refetch()} />;
  }

  const handlePdfDownload = async () => {
    try {
      setIsDownloading(true);
      setDownloadError(null);

      const blob = await reportService.downloadPdf(report.id);

      const objectUrl = URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = `investigation-report-${report.id}.pdf`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      console.error("PDF download failed:", error);
      setDownloadError("Unable to download the PDF report.");
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Breadcrumbs
        items={[
          { label: "Dashboard", to: "/dashboard" },
          { label: "Reports", to: "/reports" },
          { label: report.title },
        ]}
      />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">
            {report.title}
          </h1>

          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Generated {formatDate(report.created_at)} · Engine:{" "}
            {report.ai_engine_used ?? "n/a"} · Confidence:{" "}
            {report.confidence_score?.toFixed(0) ?? "—"}%
          </p>
        </div>

        <div className="flex flex-col items-end gap-2">
          <Button
            variant="secondary"
            onClick={handlePdfDownload}
            disabled={isDownloading}
          >
            <Download className="h-4 w-4" />
            {isDownloading ? "Downloading..." : "Download PDF"}
          </Button>

          {downloadError && (
            <p className="text-sm text-red-600 dark:text-red-400">
              {downloadError}
            </p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3">
        <Card>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Status
          </p>

          <div className="mt-2">
            <StatusBadge status={report.status} />
          </div>
        </Card>

        <Card>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Overall Risk
          </p>

          <div className="mt-2">
            <RiskBadge level={report.risk_level} />
          </div>
        </Card>

        <Card>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Risk Score
          </p>

          <p className="mt-2 text-lg font-semibold text-slate-900 dark:text-white">
            {formatRiskScore(report.risk_score)}
          </p>
        </Card>
      </div>

      <ReportSection
        title="Executive Summary"
        content={report.executive_summary}
      />

      <ReportSection
        title="Threat Analysis"
        content={report.threat_analysis}
      />

      <ReportSection
        title="Technical Summary"
        content={report.technical_summary}
      />

      <ReportSection
        title="Investigation Summary"
        content={report.investigation_summary}
      />

      <ReportSection
        title="Risk Explanation"
        content={report.risk_explanation}
      />

      {report.indicators_of_compromise &&
        report.indicators_of_compromise.length > 0 && (
          <Card>
            <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
              Indicators of Compromise
            </h2>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    <th className="py-2 pr-4 font-medium">Type</th>
                    <th className="py-2 pr-4 font-medium">Value</th>
                    <th className="py-2 pr-4 font-medium">Risk</th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {report.indicators_of_compromise.map((ioc, index) => (
                    <tr key={index}>
                      <td className="py-2 pr-4 capitalize">
                        {ioc.type.replace("_", " ")}
                      </td>

                      <td className="break-all py-2 pr-4 font-mono text-xs">
                        {ioc.value}
                      </td>

                      <td className="py-2 pr-4">
                        <RiskBadge level={ioc.risk_level} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

      {report.mitre_attack_mapping &&
        report.mitre_attack_mapping.length > 0 && (
          <Card>
            <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
              MITRE ATT&amp;CK Mapping
            </h2>

            <div className="space-y-3">
              {report.mitre_attack_mapping.map((technique) => (
                <div
                  key={technique.technique_id}
                  className="rounded-lg border border-slate-200 p-3 dark:border-slate-800"
                >
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-slate-900 px-2 py-0.5 text-xs font-mono text-white dark:bg-slate-700">
                      {technique.technique_id}
                    </span>

                    <span className="font-medium text-slate-900 dark:text-white">
                      {technique.technique_name}
                    </span>
                  </div>

                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    {technique.tactic}
                  </p>

                  <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
                    {technique.description}
                  </p>
                </div>
              ))}
            </div>
          </Card>
        )}

      {report.evidence_timeline &&
        report.evidence_timeline.length > 0 && (
          <Card>
            <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
              Evidence Timeline
            </h2>

            <ol className="relative space-y-4 border-l border-slate-200 pl-4 dark:border-slate-800">
              {report.evidence_timeline.map((event, index) => (
                <li key={index} className="relative">
                  <span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-brand-500" />

                  <p className="text-xs text-slate-400">
                    {formatDate(event.timestamp)}
                  </p>

                  <p className="text-sm text-slate-700 dark:text-slate-300">
                    {event.event}
                  </p>
                </li>
              ))}
            </ol>
          </Card>
        )}

      {report.ai_recommendations &&
        report.ai_recommendations.length > 0 && (
          <Card>
            <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
              AI Recommendations
            </h2>

            <ul className="list-inside list-disc space-y-1 text-sm text-slate-600 dark:text-slate-400">
              {report.ai_recommendations.map(
                (recommendation, index) => (
                  <li key={index}>{recommendation}</li>
                ),
              )}
            </ul>
          </Card>
        )}
    </div>
  );
}

function ReportSection({
  title,
  content,
}: {
  title: string;
  content: string | null;
}) {
  if (!content) return null;

  return (
    <Card>
      <h2 className="mb-3 font-semibold text-slate-900 dark:text-white">
        {title}
      </h2>

      <div className="prose prose-sm max-w-none text-slate-600 dark:prose-invert dark:text-slate-400">
        <ReactMarkdown>{content}</ReactMarkdown>
      </div>
    </Card>
  );
}