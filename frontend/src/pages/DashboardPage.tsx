import { Link } from "react-router-dom";
import { Search, FileText, ShieldAlert, Activity, Upload, Plus } from "lucide-react";
import { useInvestigations } from "@/hooks/useInvestigations";
import { useReports } from "@/hooks/useReports";
import { StatCard, Card } from "@/components/Card";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { CardSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/StateViews";
import { formatDate, truncate } from "@/utils/formatters";
import type { RiskLevel } from "@/types/investigation";

export function DashboardPage() {
  const { data: investigationData, isLoading: investigationsLoading } =
    useInvestigations({ page: 1, page_size: 100 });
  const { data: recentInvestigations, isLoading: recentLoading } =
    useInvestigations({ page: 1, page_size: 5 });
  const { data: reportsData, isLoading: reportsLoading } = useReports({
    page: 1,
    page_size: 5,
  });

  const riskCounts: Record<RiskLevel, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  investigationData?.items.forEach((investigation) => {
    if (investigation.risk_level) {
      riskCounts[investigation.risk_level] += 1;
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">
            Dashboard
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Overview of your investigations and generated reports.
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            to="/investigations?new=true"
            className="inline-flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-medium text-white hover:bg-brand-700"
          >
            <Plus className="h-4 w-4" />
            New Investigation
          </Link>
        </div>
      </div>

      {investigationsLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Total Investigations"
            value={investigationData?.total ?? 0}
            icon={<Search className="h-5 w-5" />}
            accent="brand"
          />
          <StatCard
            label="High Risk"
            value={riskCounts.high}
            icon={<ShieldAlert className="h-5 w-5" />}
            accent="risk-high"
          />
          <StatCard
            label="Critical Risk"
            value={riskCounts.critical}
            icon={<Activity className="h-5 w-5" />}
            accent="risk-critical"
          />
          <StatCard
            label="Reports Generated"
            value={reportsData?.total ?? 0}
            icon={<FileText className="h-5 w-5" />}
            accent="brand"
          />
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="font-semibold text-slate-900 dark:text-white">
              Recent Investigations
            </h2>
            <Link
              to="/investigations"
              className="text-sm text-brand-600 hover:underline"
            >
              View all
            </Link>
          </div>

          {recentLoading ? (
            <div className="space-y-3">
              <CardSkeleton />
            </div>
          ) : !recentInvestigations?.items.length ? (
            <EmptyState
              title="No investigations yet"
              description="Start your first OSINT investigation to see it here."
            />
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {recentInvestigations.items.map((investigation) => (
                <Link
                  key={investigation.id}
                  to={`/investigations/${investigation.id}`}
                  className="flex items-center justify-between py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50"
                >
                  <div>
                    <p className="text-sm font-medium text-slate-900 dark:text-white">
                      {truncate(investigation.target, 40)}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {investigation.investigation_type} ·{" "}
                      {formatDate(investigation.created_at)}
                    </p>
                  </div>
                  <RiskBadge level={investigation.risk_level} />
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <h2 className="mb-4 font-semibold text-slate-900 dark:text-white">
            Risk Distribution
          </h2>
          <div className="space-y-3">
            {(["critical", "high", "medium", "low"] as RiskLevel[]).map((level) => (
              <div key={level} className="flex items-center justify-between">
                <RiskBadge level={level} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  {riskCounts[level]}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="font-semibold text-slate-900 dark:text-white">
            Latest Reports
          </h2>
          <Link to="/reports" className="text-sm text-brand-600 hover:underline">
            View all
          </Link>
        </div>

        {reportsLoading ? (
          <CardSkeleton />
        ) : !reportsData?.items.length ? (
          <EmptyState
            title="No reports yet"
            description="Generate a report from one or more investigations."
            icon={<FileText className="h-8 w-8" />}
          />
        ) : (
          <div className="divide-y divide-slate-100 dark:divide-slate-800">
            {reportsData.items.map((report) => (
              <Link
                key={report.id}
                to={`/reports/${report.id}`}
                className="flex items-center justify-between py-3 hover:bg-slate-50 dark:hover:bg-slate-800/50"
              >
                <div>
                  <p className="text-sm font-medium text-slate-900 dark:text-white">
                    {truncate(report.title, 50)}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {formatDate(report.created_at)}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <StatusBadge status={report.status} />
                  <RiskBadge level={report.risk_level} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>

      <Card>
        <h2 className="mb-4 font-semibold text-slate-900 dark:text-white">
          Quick Actions
        </h2>
        <div className="flex flex-wrap gap-3">
          <Link
            to="/investigations?new=true"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
          >
            <Search className="h-4 w-4" />
            New Investigation
          </Link>
          <Link
            to="/investigations?new=true&new_type=file"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
          >
            <Upload className="h-4 w-4" />
            Upload File
          </Link>
          <Link
            to="/reports"
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800"
          >
            <FileText className="h-4 w-4" />
            Generate Report
          </Link>
        </div>
      </Card>
    </div>
  );
}
