import { apiClient } from "./apiClient";
import type { PaginatedResponse } from "@/types/investigation";
import type { Report, ReportStatus, ReportSummary } from "@/types/report";

export interface ListReportsParams {
  page?: number;
  page_size?: number;
  status?: ReportStatus;
  query?: string;
}

export const reportService = {
  async generate(investigationIds: string[], title?: string): Promise<Report> {
    const response = await apiClient.post<Report>("/reports/generate", {
      investigation_ids: investigationIds,
      title: title || null,
    });

    return response.data;
  },

  async list(
    params: ListReportsParams = {}
  ): Promise<PaginatedResponse<ReportSummary>> {
    const response = await apiClient.get<PaginatedResponse<ReportSummary>>(
      "/reports",
      { params }
    );

    return response.data;
  },

  async get(id: string): Promise<Report> {
    const response = await apiClient.get<Report>(`/reports/${id}`);

    return response.data;
  },

  async remove(id: string): Promise<void> {
    await apiClient.delete(`/reports/${id}`);
  },

  async getMarkdown(id: string): Promise<string> {
    const response = await apiClient.get(`/reports/${id}`, {
      params: { format: "markdown" },
      responseType: "text",
    });

    return response.data;
  },

  async downloadPdf(id: string): Promise<Blob> {
    const response = await apiClient.get(`/reports/${id}`, {
      params: { format: "pdf" },
      responseType: "blob",
    });

    return response.data;
  },

  async downloadPdfToBrowser(id: string, filename = `report-${id}.pdf`): Promise<void> {
    const blob = await this.downloadPdf(id);
    const objectUrl = URL.createObjectURL(blob);
    try {
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = filename;
      anchor.click();
    } finally {
      URL.revokeObjectURL(objectUrl);
    }
  },
};