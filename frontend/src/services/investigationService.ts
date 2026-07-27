import { apiClient } from "./apiClient";
import type {
  Investigation,
  InvestigationStatus,
  InvestigationType,
  PaginatedResponse,
  InvestigationSummary,
} from "@/types/investigation";

export interface ListInvestigationsParams {
  page?: number;
  page_size?: number;
  type?: InvestigationType;
  status?: InvestigationStatus;
  query?: string;
}

export const investigationService = {
  async list(
    params: ListInvestigationsParams = {}
  ): Promise<PaginatedResponse<InvestigationSummary>> {
    const response = await apiClient.get<PaginatedResponse<InvestigationSummary>>(
      "/investigations",
      { params }
    );

    return response.data;
  },

  async get(id: string): Promise<Investigation> {
    const response = await apiClient.get<Investigation>(
      `/investigations/${id}`
    );

    return response.data;
  },

  async remove(id: string): Promise<void> {
    await apiClient.delete(`/investigations/${id}`);
  },

  async createUsername(username: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/username/investigate",
      { username }
    );

    return response.data;
  },

  async createEmail(email: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/email/investigate",
      { email }
    );

    return response.data;
  },

  async createDomain(target: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/domain/investigate",
      { target }
    );

    return response.data;
  },

  async createIp(target: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/ip/investigate",
      { target }
    );

    return response.data;
  },

  async createDns(domain: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/dns-intelligence/investigate",
      { domain }
    );

    return response.data;
  },

  async createUrl(url: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/url/investigate",
      { url }
    );

    return response.data;
  },

  async createPhone(phoneNumber: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/phone/investigate",
      { phone_number: phoneNumber }
    );

    return response.data;
  },

  async createBreach(target: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/breach/investigate",
      { target }
    );

    return response.data;
  },

  async createThreatIntelligence(target: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/threat-intelligence/investigate",
      { target }
    );

    return response.data;
  },

  async createSocialMedia(username: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/social-media/investigate",
      {
        username,
        related_usernames: [],
      }
    );

    return response.data;
  },

  async createMalware(fileHash: string): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/malware/investigate",
      { file_hash: fileHash }
    );

    return response.data;
  },

  async createRiskAssessment(
    investigationIds: string[],
    label?: string
  ): Promise<Investigation> {
    const response = await apiClient.post<Investigation>(
      "/investigations/risk-assessment/investigate",
      {
        investigation_ids: investigationIds,
        label: label || "Composite Risk Assessment",
      }
    );

    return response.data;
  },

  async uploadFile(
    file: File
  ): Promise<{ investigation: Investigation }> {
    const formData = new FormData();
    formData.append("file", file);

    const response = await apiClient.post(
      "/investigations/file/upload",
      formData
    );

    return response.data;
  },

  async uploadReverseImage(
    file: File
  ): Promise<{ investigation: Investigation }> {
    const formData = new FormData();
    formData.append("file", file);

    const response = await apiClient.post(
      "/investigations/reverse-image/upload",
      formData
    );

    return response.data;
  },

  async analyzeIoc(
    indicator: string
  ): Promise<{
    detected_type: InvestigationType;
    investigation: Investigation;
  }> {
    const response = await apiClient.post(
      "/investigations/ioc/analyze",
      { indicator }
    );

    return response.data;
  },
};