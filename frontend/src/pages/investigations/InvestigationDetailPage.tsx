import { useParams, useNavigate, Link } from "react-router-dom";
import { Loader2 } from "lucide-react";

import { useInvestigation } from "@/hooks/useInvestigations";
import { useGenerateReport } from "@/hooks/useReports";
import { useToast } from "@/contexts/ToastContext";
import { Card } from "@/components/Card";
import { RiskBadge } from "@/components/Badge";
import { CardSkeleton } from "@/components/LoadingSkeleton";
import { ErrorState } from "@/components/StateViews";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { formatRiskScore } from "@/utils/formatters";

import { InvestigationHeader } from "@/components/investigation-result/InvestigationHeader";
import { IntelligenceSection } from "@/components/investigation-result/IntelligenceSection";
import { EvidenceList } from "@/components/investigation-result/EvidenceList";

export function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { showToast } = useToast();
  const { data: investigation, isLoading, isError, refetch } = useInvestigation(id);
  const generateReport = useGenerateReport();

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

  const hasDedicatedIntelligence =
    investigation.investigation_type === "reverse_image" ||
    investigation.investigation_type === "file";

  return (
    <div className="space-y-6">
      <Breadcrumbs
        items={[
          { label: "Dashboard", to: "/dashboard" },
          { label: "Investigations", to: "/investigations" },
          { label: investigation.target },
        ]}
      />

      <InvestigationHeader
        investigation={investigation}
        onGenerateReport={handleGenerateReport}
        isGeneratingReport={generateReport.isPending}
      />

      {/*
        Pre-Account-2 placeholder. This becomes AssessmentDimensions
        (Security Risk / Digital Exposure / Confidence / Coverage)
        once Account 2's evidence architecture is integrated - see
        ACCOUNT3_PARTC_DESIGN.md section 8. risk_score/risk_level are
        real existing backend fields, not fabricated; they are simply
        the values Account 2's work will supersede, not values Part C1
        invented.
      */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
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

      <IntelligenceSection investigation={investigation} />

      <EvidenceList
        results={investigation.results}
        title={hasDedicatedIntelligence ? "All Evidence Sources" : "Evidence"}
      />

      {generateReport.isPending && (
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" />
          Generating AI-correlated report…
        </div>
      )}

      <Link
        to="/investigations"
        className="inline-block text-sm text-brand-600 hover:underline"
      >
        ← Back to Investigations
      </Link>
    </div>
  );
}
