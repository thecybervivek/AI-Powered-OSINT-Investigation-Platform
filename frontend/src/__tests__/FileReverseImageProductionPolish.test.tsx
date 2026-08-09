import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { FileIntelligence } from "@/components/investigation-result/modules/FileIntelligence";
import { ReverseImageIntelligence } from "@/components/investigation-result/modules/ReverseImageIntelligence";
import type { InvestigationResult } from "@/types/investigation";

function makeResult(overrides: Partial<InvestigationResult>): InvestigationResult {
  return {
    id: overrides.id ?? "result-1",
    source: "example",
    status: "success",
    data: {},
    error_message: null,
    latency_ms: 100,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderFile(results: InvestigationResult[]) {
  return render(
    <MemoryRouter>
      <FileIntelligence results={results} />
    </MemoryRouter>
  );
}

function renderReverseImage(results: InvestigationResult[]) {
  return render(
    <MemoryRouter>
      <ReverseImageIntelligence results={results} />
    </MemoryRouter>
  );
}

describe("FileIntelligence production polish", () => {
  it("shows the exact required assessment label, never a numeric score", () => {
    renderFile([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "no_malicious_evidence_detected",
          label: "No malicious evidence detected",
          reasoning: [],
          providers_consulted: ["virustotal"],
          providers_unavailable: [],
          providers_failed: [],
        },
      }),
    ]);

    expect(screen.getByText("No malicious evidence detected")).toBeInTheDocument();
    expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
  });

  it("shows File Structure entropy and a packed-file callout when entropy is high", () => {
    renderFile([
      makeResult({
        source: "file_integrity",
        data: { entropy: 7.8, high_entropy: true, entropy_threshold: 7.2 },
      }),
    ]);

    expect(screen.getByText("File Structure")).toBeInTheDocument();
    expect(screen.getByText("7.8 bits/byte")).toBeInTheDocument();
    expect(screen.getByText(/may be/i)).toBeInTheDocument();
    expect(screen.getByText(/not itself a malicious indicator/i)).toBeInTheDocument();
  });

  it("summarizes VirusTotal with a detection count instead of a bare Success badge", () => {
    renderFile([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "malicious",
          label: "Malicious indicators detected",
          reasoning: [],
          providers_consulted: ["virustotal"],
          providers_unavailable: [],
          providers_failed: [],
        },
      }),
      makeResult({
        source: "virustotal_file",
        status: "success",
        data: { analysis_stats: { malicious: 12, harmless: 60 } },
      }),
    ]);

    expect(screen.getByText("12 / 72 detections")).toBeInTheDocument();
  });

  it("lists unavailable malware intelligence providers and a plain YARA line, without marking the investigation failed", () => {
    renderFile([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "threat_assessment_incomplete",
          label: "Threat assessment incomplete",
          reasoning: [],
          providers_consulted: [],
          providers_unavailable: ["virustotal", "malwarebazaar", "hybrid_analysis", "otx"],
          providers_failed: [],
        },
      }),
      makeResult({ source: "yara_scan", status: "success", data: { matched: false, match_count: 0 } }),
    ]);

    expect(screen.getByText("Unavailable Providers")).toBeInTheDocument();
    expect(screen.getByText("VirusTotal unavailable.")).toBeInTheDocument();
    expect(screen.getByText(/No matching YARA rules\./)).toBeInTheDocument();
  });

  it("shows digital signature info from VirusTotal when available, and an honest 'not checked' state otherwise", () => {
    renderFile([
      makeResult({
        source: "virustotal_file",
        status: "success",
        data: { signature_info: { product: "Acrobat Reader", verified: "Signed" } },
      }),
    ]);

    expect(screen.getByText("Digital Signature")).toBeInTheDocument();
    expect(screen.getByText("Acrobat Reader")).toBeInTheDocument();
  });

  it("shows 'not checked' for digital signature when VirusTotal did not run", () => {
    renderFile([makeResult({ source: "hash_analysis", data: { md5: "x" } })]);

    expect(screen.getByText(/Not checked/i)).toBeInTheDocument();
  });
});

describe("ReverseImageIntelligence production polish", () => {
  it("shows 'Image matches found' rather than a numeric score when an internal match exists", () => {
    renderReverseImage([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "image_matches_found",
          label: "Image matches found",
          reasoning: ["Identical to a previously investigated image"],
          providers_unavailable: ["google_lens", "tineye"],
        },
      }),
    ]);

    expect(screen.getByText("Image matches found")).toBeInTheDocument();
    expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
  });

  it("lists all six named public reverse-image providers as unavailable, never implying they ran", () => {
    renderReverseImage([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "no_public_matches_found",
          label: "No public matches found",
          reasoning: [],
          providers_unavailable: [
            "google_lens",
            "bing_visual_search",
            "tineye",
            "yandex",
            "saucenao",
            "iqdb",
          ],
        },
      }),
    ]);

    expect(screen.getByText("Unavailable Providers")).toBeInTheDocument();
    expect(screen.getByText("Google Lens")).toBeInTheDocument();
    expect(screen.getByText("TinEye")).toBeInTheDocument();
    expect(screen.getByText("SauceNAO")).toBeInTheDocument();
    expect(screen.getByText("IQDB")).toBeInTheDocument();
    expect(
      screen.getByText(/not a public web search/i)
    ).toBeInTheDocument();
  });
});
