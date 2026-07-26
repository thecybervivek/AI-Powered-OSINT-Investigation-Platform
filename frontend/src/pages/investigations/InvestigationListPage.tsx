import { useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import { Plus, Search as SearchIcon, Trash2, Upload } from "lucide-react";
import { useInvestigations, useDeleteInvestigation } from "@/hooks/useInvestigations";
import { investigationService } from "@/services/investigationService";
import { useToast } from "@/contexts/ToastContext";
import { Card } from "@/components/Card";
import { Button } from "@/components/Button";
import { RiskBadge, StatusBadge } from "@/components/Badge";
import { TableSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState, ErrorState } from "@/components/StateViews";
import { Modal, ConfirmDialog } from "@/components/Modal";
import { Pagination } from "@/components/Pagination";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { formatDate, truncate } from "@/utils/formatters";
import type {
  InvestigationStatus,
  InvestigationType,
} from "@/types/investigation";

const TYPE_OPTIONS: { value: InvestigationType; label: string }[] = [
  { value: "username", label: "Username" },
  { value: "email", label: "Email" },
  { value: "domain", label: "Domain" },
  { value: "ip_address", label: "IP Address" },
  { value: "url", label: "URL" },
  { value: "file", label: "File" },
];

const STATUS_OPTIONS: InvestigationStatus[] = [
  "queued",
  "running",
  "completed",
  "failed",
  "partial",
];

export function InvestigationListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { showToast } = useToast();

  const page = Number(searchParams.get("page") ?? "1");
  const query = searchParams.get("q") ?? "";
  const typeFilter = (searchParams.get("type") as InvestigationType) || undefined;
  const statusFilter = (searchParams.get("status") as InvestigationStatus) || undefined;
  const isNewModalOpen = searchParams.get("new") === "true";

  const [searchInput, setSearchInput] = useState(query);
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);

  const { data, isLoading, isError, refetch } = useInvestigations({
    page,
    page_size: 10,
    query: query || undefined,
    type: typeFilter,
    status: statusFilter,
  });

  const deleteMutation = useDeleteInvestigation();

  function updateParams(updates: Record<string, string | undefined>) {
    const next = new URLSearchParams(searchParams);

    Object.entries(updates).forEach(([key, value]) => {
      if (value) {
        next.set(key, value);
      } else {
        next.delete(key);
      }
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
      showToast("success", "Investigation deleted.");
    } catch {
      showToast("error", "Failed to delete investigation.");
    } finally {
      setDeleteTargetId(null);
    }
  }

  return (
    <div className="space-y-6">
      <Breadcrumbs items={[{ label: "Dashboard", to: "/dashboard" }, { label: "Investigations" }]} />

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-slate-900 dark:text-white">
          Investigations
        </h1>
        <Button onClick={() => updateParams({ new: "true" })}>
          <Plus className="h-4 w-4" />
          New Investigation
        </Button>
      </div>

      <Card>
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <form onSubmit={handleSearchSubmit} className="flex flex-1 min-w-[200px] gap-2">
            <input
              value={searchInput}
              onChange={(event) => setSearchInput(event.target.value)}
              placeholder="Search by target…"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
            />
            <Button type="submit" variant="secondary">
              <SearchIcon className="h-4 w-4" />
            </Button>
          </form>

          <select
            value={typeFilter ?? ""}
            onChange={(event) =>
              updateParams({ type: event.target.value || undefined, page: "1" })
            }
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          >
            <option value="">All Types</option>
            {TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

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
            title="No investigations found"
            description="Try adjusting your filters, or start a new investigation."
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 dark:border-slate-800 dark:text-slate-400">
                    <th className="py-2 pr-4 font-medium">Target</th>
                    <th className="py-2 pr-4 font-medium">Type</th>
                    <th className="py-2 pr-4 font-medium">Status</th>
                    <th className="py-2 pr-4 font-medium">Risk</th>
                    <th className="py-2 pr-4 font-medium">Created</th>
                    <th className="py-2 pr-4 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {data.items.map((investigation) => (
                    <tr key={investigation.id}>
                      <td className="py-3 pr-4">
                        <Link
                          to={`/investigations/${investigation.id}`}
                          className="font-medium text-brand-600 hover:underline"
                        >
                          {truncate(investigation.target, 40)}
                        </Link>
                      </td>
                      <td className="py-3 pr-4 capitalize text-slate-600 dark:text-slate-400">
                        {investigation.investigation_type.replace("_", " ")}
                      </td>
                      <td className="py-3 pr-4">
                        <StatusBadge status={investigation.status} />
                      </td>
                      <td className="py-3 pr-4">
                        <RiskBadge level={investigation.risk_level} />
                      </td>
                      <td className="py-3 pr-4 text-slate-500 dark:text-slate-400">
                        {formatDate(investigation.created_at)}
                      </td>
                      <td className="py-3 pr-4 text-right">
                        <button
                          onClick={() => setDeleteTargetId(investigation.id)}
                          aria-label={`Delete investigation for ${investigation.target}`}
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

      <NewInvestigationModal
        isOpen={isNewModalOpen}
        onClose={() => updateParams({ new: undefined, type: undefined })}
        onCreated={(id) => {
          updateParams({ new: undefined });
          navigate(`/investigations/${id}`);
        }}
      />

      <ConfirmDialog
        isOpen={Boolean(deleteTargetId)}
        title="Delete Investigation"
        message="This will permanently delete the investigation and all its results. This cannot be undone."
        confirmLabel="Delete"
        isDangerous
        isLoading={deleteMutation.isPending}
        onConfirm={handleConfirmDelete}
        onCancel={() => setDeleteTargetId(null)}
      />
    </div>
  );
}

function NewInvestigationModal({
  isOpen,
  onClose,
  onCreated,
}: {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const { showToast } = useToast();
  const [type, setType] = useState<InvestigationType>("username");
  const [value, setValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setIsSubmitting(true);

    try {
      let investigationId: string;

      switch (type) {
        case "username": {
          const result = await investigationService.createUsername(value);
          investigationId = result.id;
          break;
        }
        case "email": {
          const result = await investigationService.createEmail(value);
          investigationId = result.id;
          break;
        }
        case "domain": {
          const result = await investigationService.createDomain(value);
          investigationId = result.id;
          break;
        }
        case "ip_address": {
          const result = await investigationService.createIp(value);
          investigationId = result.id;
          break;
        }
        case "url": {
          const result = await investigationService.createUrl(value);
          investigationId = result.id;
          break;
        }
        case "file": {
          if (!file) throw new Error("Please choose a file.");
          const result = await investigationService.uploadFile(file);
          investigationId = result.investigation.id;
          break;
        }
        default:
          throw new Error("Unsupported investigation type.");
      }

      showToast("success", "Investigation started.");
      setValue("");
      setFile(null);
      onCreated(investigationId);
    } catch {
      showToast("error", "Failed to start investigation. Please check your input.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="New Investigation">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
            Investigation Type
          </label>
          <select
            value={type}
            onChange={(event) => setType(event.target.value as InvestigationType)}
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-white"
          >
            {TYPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        {type === "file" ? (
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
              File
            </label>
            <label className="flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-dashed border-slate-300 px-4 py-6 text-sm text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-800">
              <Upload className="h-4 w-4" />
              {file ? file.name : "Choose a file to upload"}
              <input
                type="file"
                className="hidden"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              />
            </label>
          </div>
        ) : (
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
              Target
            </label>
            <input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={
                type === "email"
                  ? "person@example.com"
                  : type === "url"
                  ? "https://example.com/path"
                  : type === "ip_address"
                  ? "203.0.113.5"
                  : type === "domain"
                  ? "example.com"
                  : "username"
              }
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-slate-800 dark:text-white"
              required
            />
          </div>
        )}

        <div className="flex justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting}>
            Start Investigation
          </Button>
        </div>
      </form>
    </Modal>
  );
}
