import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { ToastProvider } from "@/contexts/ToastContext";
import { InvestigationDetailPage } from "@/pages/investigations/InvestigationDetailPage";
import { useInvestigation } from "@/hooks/useInvestigations";
import { useGenerateReport } from "@/hooks/useReports";
import type { Investigation, InvestigationResult } from "@/types/investigation";

vi.mock("@/hooks/useInvestigations", () => ({
  useInvestigation: vi.fn(),
}));

vi.mock("@/hooks/useReports", () => ({
  useGenerateReport: vi.fn(),
}));

const mockedUseInvestigation = vi.mocked(useInvestigation);
const mockedUseGenerateReport = vi.mocked(useGenerateReport);

function makeResult(overrides: Partial<InvestigationResult>): InvestigationResult {
  return {
    id: overrides.id ?? "result-1",
    source: "example_provider",
    status: "success",
    data: {},
    error_message: null,
    latency_ms: 100,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function makeInvestigation(overrides: Partial<Investigation>): Investigation {
  return {
    id: "inv-1",
    investigation_type: "username",
    target: "johndoe",
    status: "completed",
    risk_score: null,
    risk_level: null,
    summary: null,
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:05:00Z",
    error_message: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:05:00Z",
    results: [],
    ...overrides,
  };
}

function renderPage(investigation: Investigation | undefined, queryOverrides = {}) {
  mockedUseInvestigation.mockReturnValue({
    data: investigation,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
    ...queryOverrides,
  } as unknown as ReturnType<typeof useInvestigation>);

  const mutateAsync = vi.fn().mockResolvedValue({ id: "report-1" });
  mockedUseGenerateReport.mockReturnValue({
    mutateAsync,
    isPending: false,
  } as unknown as ReturnType<typeof useGenerateReport>);

  const utils = render(
    <MemoryRouter initialEntries={[`/investigations/${investigation?.id ?? "inv-1"}`]}>
      <ToastProvider>
        <Routes>
          <Route path="/investigations/:id" element={<InvestigationDetailPage />} />
          <Route path="/reports/:id" element={<div>Report Page</div>} />
        </Routes>
      </ToastProvider>
    </MemoryRouter>
  );

  return { ...utils, mutateAsync };
}

describe("InvestigationDetailPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows a queued notice with no fabricated progress", () => {
    renderPage(makeInvestigation({ status: "queued", results: [] }));

    expect(
      screen.getByText(/hasn't started collecting evidence yet/i)
    ).toBeInTheDocument();
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it("shows a running notice and mentions the page updates automatically", () => {
    renderPage(makeInvestigation({ status: "running", results: [] }));

    expect(screen.getByText(/in progress/i)).toBeInTheDocument();
    expect(screen.getByText(/updates automatically/i)).toBeInTheDocument();
  });

  it("shows a partial notice that does not equate missing sources with a clean result", () => {
    renderPage(
      makeInvestigation({
        status: "partial",
        results: [makeResult({ status: "failed", error_message: null })],
      })
    );

    expect(screen.getByText(/partial results/i)).toBeInTheDocument();
    expect(screen.getByText(/not cleared/i)).toBeInTheDocument();
  });

  it("shows the failure reason for a failed investigation", () => {
    renderPage(
      makeInvestigation({
        status: "failed",
        error_message: "Upstream validation failed.",
        results: [],
      })
    );

    expect(screen.getByText("Upstream validation failed.")).toBeInTheDocument();
  });

  it("renders no extra status notice for a completed investigation", () => {
    renderPage(makeInvestigation({ status: "completed" }));

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("falls back to the generic EvidenceList for a type with no dedicated renderer", () => {
    renderPage(
      makeInvestigation({
        investigation_type: "username",
        results: [makeResult({ source: "sherlock", status: "success" })],
      })
    );

    expect(screen.getByText("Evidence (1 source)")).toBeInTheDocument();
    expect(screen.getByText("sherlock")).toBeInTheDocument();
  });

  it("renders the Reverse Image dedicated renderer plus the full evidence list", () => {
    renderPage(
      makeInvestigation({
        investigation_type: "reverse_image",
        target: "9f3a...sha256",
        results: [
          makeResult({
            id: "r1",
            source: "hash_analysis",
            status: "success",
            data: {
              md5: "d41d8cd98f00b204e9800998ecf8427e",
              sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
              sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              sha512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3",
            },
          }),
          makeResult({
            id: "r2",
            source: "perceptual_hashing",
            status: "success",
            data: { phash: "abc123", ahash: "def456", dhash: "ghi789", width: 64, height: 64 },
          }),
          makeResult({
            id: "r3",
            source: "duplicate_detection",
            status: "success",
            data: {
              exact_duplicate_found: false,
              exact_duplicate_investigation_id: null,
              near_duplicate_found: false,
              closest_match_investigation_id: null,
              closest_match_hamming_distance: null,
              similarity_score: null,
            },
          }),
        ],
      })
    );

    expect(screen.getByText("Cryptographic Fingerprints")).toBeInTheDocument();
    expect(
      screen.getByText("d41d8cd98f00b204e9800998ecf8427e")
    ).toBeInTheDocument();
    expect(screen.getByText("Perceptual Fingerprints")).toBeInTheDocument();
    expect(
      screen.getByText(/measure visual similarity, not/i)
    ).toBeInTheDocument();
    expect(screen.getByText("None found")).toBeInTheDocument();

    // Nothing is hidden: the same sources still appear in the full evidence list below.
    expect(screen.getByText("All Evidence Sources (3 sources)")).toBeInTheDocument();
  });

  it("renders the File Analysis dedicated renderer without claiming a filename that isn't available", () => {
    renderPage(
      makeInvestigation({
        investigation_type: "file",
        results: [
          makeResult({
            id: "r1",
            source: "file_validation",
            status: "success",
            data: {
              declared_extension: ".pdf",
              detected_mime_type: "application/pdf",
              file_size_bytes: 204800,
              has_double_extension: false,
              suspicious_extension: false,
              errors: [],
            },
          }),
        ],
      })
    );

    expect(screen.getByText("File Overview")).toBeInTheDocument();
    expect(screen.getByText("application/pdf")).toBeInTheDocument();
    expect(screen.getByText("200.0 KB")).toBeInTheDocument();
    expect(screen.queryByText(/^Filename$/i)).not.toBeInTheDocument();
  });

  it("calls generateReport with this investigation's id and navigates to the new report", async () => {
    const user = userEvent.setup();
    const { mutateAsync } = renderPage(makeInvestigation({ id: "inv-42" }));

    await user.click(screen.getByRole("button", { name: /generate report/i }));

    expect(mutateAsync).toHaveBeenCalledWith({ investigationIds: ["inv-42"] });
    expect(await screen.findByText("Report Page")).toBeInTheDocument();
  });

  // ==========================================================
  // Domain Investigation production polish
  // ==========================================================

  it("does not show a numeric Risk Score or Risk Level for a domain investigation", () => {
    renderPage(
      makeInvestigation({
        investigation_type: "domain",
        target: "example.com",
        risk_score: 0,
        risk_level: "low",
        results: [
          makeResult({
            id: "r1",
            source: "threat_assessment",
            status: "success",
            data: {
              state: "threat_assessment_incomplete",
              label: "Threat assessment incomplete",
              reasoning: [],
              providers_consulted: [],
              providers_unavailable: ["shodan", "censys", "greynoise", "otx"],
              providers_failed: [],
            },
          }),
        ],
      })
    );

    expect(screen.queryByText("Risk Score")).not.toBeInTheDocument();
    expect(screen.queryByText("Risk Level")).not.toBeInTheDocument();
    expect(screen.queryByText("0.0/100")).not.toBeInTheDocument();
    expect(screen.getByText("Threat assessment incomplete")).toBeInTheDocument();
  });

  it("still shows Risk Score/Level for non-domain investigation types (no regression)", () => {
    renderPage(
      makeInvestigation({
        investigation_type: "username",
        risk_score: 12.5,
        risk_level: "low",
      })
    );

    expect(screen.getByText("Risk Score")).toBeInTheDocument();
    expect(screen.getByText("Risk Level")).toBeInTheDocument();
  });

  it("collapses the raw evidence list behind a toggle for domain investigations, without losing any of it", async () => {
    const user = userEvent.setup();

    renderPage(
      makeInvestigation({
        investigation_type: "domain",
        target: "example.com",
        results: [
          makeResult({ id: "r1", source: "whois", status: "success", data: { registered: true } }),
          makeResult({ id: "r2", source: "asn_lookup:1.2.3.4", status: "success" }),
        ],
      })
    );

    // Not shown by default - grouped sections cover the same ground.
    expect(screen.queryByText("whois")).not.toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: /show raw evidence sources \(2\)/i });
    expect(toggle).toBeInTheDocument();

    await user.click(toggle);

    expect(screen.getByText("whois")).toBeInTheDocument();
    expect(screen.getByText(/asn lookup \(1\.2\.3\.4\)/i)).toBeInTheDocument();
  });

  it("does not collapse evidence for non-domain types with a dedicated renderer (no regression)", () => {
    renderPage(
      makeInvestigation({
        investigation_type: "reverse_image",
        target: "abc123sha256",
        results: [makeResult({ id: "r1", source: "hash_analysis", status: "success" })],
      })
    );

    expect(screen.getByText("hash analysis")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /show raw evidence sources/i })
    ).not.toBeInTheDocument();
  });
});
