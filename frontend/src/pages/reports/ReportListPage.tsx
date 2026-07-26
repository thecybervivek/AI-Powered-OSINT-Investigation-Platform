import { useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { Trash2 } from "lucide-react";
import { useReports, useDeleteReport } from "@/hooks/useReports";
import { useToast } from "@/contexts/ToastContext";
import { Card } from "@/components/Card";
import { Button } from "@/components/Button";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { TableSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState, ErrorState } from "@/components/StateViews";
import { ConfirmDialog } from "@/components/Modal";
import { Pagination } from "@/components/Pagination";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { formatDate, truncate } from "@/utils/formatters";
import type { ReportStatus } from "@/types/report";

const STATUS_OPTIONS: ReportStatus[] = ["generating", "completed", "failed"];

export function ReportListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { showToast } = useToast();

  const page = Number(searchParams.get("page") ?? "1");
  const query = searchParams.get("q") ?? "";
  const statusFilter = (searchParams.get("status") as ReportStatus) || undefined;

  const [searchInput, setSearchInput] = useState(query);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);

  const { data, isLoading, isError, refetch } = useReports({
    page,
    page_size: 10,
    query: query || undefined,
    status: statusFilter,
  });

  const deleteMutation = useDeleteReport();

  function updateParams(updates: Record<string, string | undefined>) {
    const next = new URLSearchParams(searchParams);

    Object.entries(updates).forEach(([key, value]) => {
      if (value) next.set(key, value);
      else next.delete(key);
    });

    setSearchParams(next);
  }

  function handleSearchSubmit(event: React.FormEvent) {
    event.preventDefault();
    updateParams({ q: searchInput || undefined, page: "1" });
  }

  async function handleConfirmDelete() {
    if (!deleteTargetId) return;

    try {
      await deleteMutation.mutateAsync(deleteTargetId);
      showToast("success", "Report deleted.");
    } catch {
      showToast("error", "Failed to delete report.");
    } finally {
      setDeleteTargetId(null);
    }
  }

  return (
    <div className="space-y-6">
      <Breadcrumbs items={[{ label: "Dashboard", to: "/dashboard" }, { label: "Reports" }]} />

      <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">Reports</h1>

      <Card>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <form onSubmit={handleSearchSubmit} className="flex flex-1 min-w-[200px] gap-2">
            <input
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              placeholder="Search by title…"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
            />
            <Button type="submit" variant="secondary">
              Search
            </Button>
          </form>

          <select
            value={statusFilter ?? ""}
            onChange={(event) =>
              updateParams({ status: event.target.value || undefined, page: "1" })
            }
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          >
            <option value="">All Statuses</option>
            {STATUS_OPTIONS.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </div>

        {isLoading ? (
          <TableSkeleton />
        ) : isError ? (
          <ErrorState onRetry={() => refetch()} />
        ) : !data?.items.length ? (
          <EmptyState
            title="No reports found"
            description="Generate a report from an investigation's detail page."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    <th className="py-2 pr-4 font-medium">Title</th>
                    <th className="py-2 pr-4 font-medium">Status</th>
                    <th className="py-2 pr-4 font-medium">Risk</th>
                    <th className="py-2 pr-4 font-medium">AI Engine</th>
                    <th className="py-2 pr-4 font-medium">Created</th>
                    <th className="py-2 pr-4 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {data.items.map((report) => (
                    <tr key={report.id}>
                      <td className="py-3 pr-4">
                        <Link
                          to={`/reports/${report.id}`}
                          className="font-medium text-brand-600 hover:underline"
                        >
                          {truncate(report.title, 50)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4">
                        <StatusBadge status={report.status} />
                      </td>
                      <td className="py-3 pr-4">
                        <RiskBadge level={report.risk_level} />
                      </td>
                      <td className="py-3 pr-4 text-slate-500 dark:text-slate-400">
                        {report.ai_engine_used ?? "—"}
                      </td>
                      <td className="py-3 pr-4 text-slate-500 dark:text-slate-400">
                        {formatDate(report.created_at)}
                      </td>
                      <td className="py-3 pr-4 text-right">
                        <button
                          onClick={() => setDeleteTargetId(report.id)}
                          aria-label={`Delete report ${report.title}`}
                          className="rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/30"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4">
              <Pagination
                page={data.page}
                totalPages={data.total_pages}
                onPageChange={(nextPage) => updateParams({ page: String(nextPage) })}
              />
            </div>
          </>
        )}
      </Card>

      <ConfirmDialog
        isOpen={Boolean(deleteTargetId)}
        title="Delete Report"
        message="This will permanently delete this report. This cannot be undone."
        confirmLabel="Delete"
        isDangerous
        isLoading={deleteMutation.isPending}
        onConfirm={handleConfirmDelete}
        onCancel={() => setDeleteTargetId(null)}
      />
    </div>
  );
}
