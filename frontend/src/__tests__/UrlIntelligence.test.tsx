import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { UrlIntelligence } from "@/components/investigation-result/modules/UrlIntelligence";
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

function renderUrl(results: InvestigationResult[]) {
  return render(
    <MemoryRouter>
      <UrlIntelligence results={results} />
    </MemoryRouter>
  );
}

describe("UrlIntelligence", () => {
  it("shows the exact required assessment label, never a numeric score", () => {
    renderUrl([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "no_malicious_evidence_detected",
          label: "No malicious evidence detected",
          reasoning: [],
          providers_consulted: ["virustotal_url"],
          providers_unavailable: [],
          providers_failed: [],
        },
      }),
    ]);

    expect(screen.getByText("No malicious evidence detected")).toBeInTheDocument();
    expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
  });

  it("shows redirect analysis as a chain, not just the final destination", () => {
    renderUrl([
      makeResult({
        source: "http_response",
        data: {
          original_url: "https://example.com/old",
          final_url: "https://www.example.com/new",
          redirect_chain: [
            { url: "https://example.com/old", status_code: 301 },
            { url: "https://www.example.com/new", status_code: 200 },
          ],
          http_status: 200,
          https_enforced: true,
          canonical_host: "www.example.com",
          content_type: "text/html",
          server: "nginx",
          page_title: "Example",
          favicon: null,
          security_headers: {},
        },
      }),
    ]);

    expect(screen.getByText("Redirect Analysis")).toBeInTheDocument();
    expect(screen.getByText("https://example.com/old")).toBeInTheDocument();
    expect(screen.getByText("https://www.example.com/new")).toBeInTheDocument();
    expect(screen.getByText("301 → 200")).toBeInTheDocument();
  });

  it("does not show a redirect analysis block for a direct (non-redirecting) URL", () => {
    renderUrl([
      makeResult({
        source: "http_response",
        data: {
          original_url: "https://example.com/",
          final_url: "https://example.com/",
          redirect_chain: [{ url: "https://example.com/", status_code: 200 }],
          http_status: 200,
          https_enforced: true,
          canonical_host: "example.com",
          content_type: "text/html",
          server: null,
          page_title: "Example",
          favicon: null,
          security_headers: {},
        },
      }),
    ]);

    expect(screen.queryByText("Redirect Analysis")).not.toBeInTheDocument();
    expect(screen.getByText("200")).toBeInTheDocument();
  });

  it("shows a security headers summary count and per-header presence", () => {
    renderUrl([
      makeResult({
        source: "http_response",
        data: {
          original_url: "https://example.com/",
          final_url: "https://example.com/",
          redirect_chain: [{ url: "https://example.com/", status_code: 200 }],
          http_status: 200,
          https_enforced: true,
          canonical_host: "example.com",
          security_headers: {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": null,
            "x-frame-options": "DENY",
            "x-content-type-options": null,
            "referrer-policy": null,
          },
        },
      }),
    ]);

    expect(screen.getByText("2 of 5 common security headers present.")).toBeInTheDocument();
    expect(screen.getByText("max-age=31536000")).toBeInTheDocument();
    expect(screen.getByText("DENY")).toBeInTheDocument();
  });

  it("lists unavailable threat intelligence providers including ones with no implementation, without marking the investigation failed", () => {
    renderUrl([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "threat_assessment_incomplete",
          label: "Threat assessment incomplete",
          reasoning: [],
          providers_consulted: [],
          providers_unavailable: [
            "google_safe_browsing",
            "phishtank",
            "virustotal_url",
            "urlscan",
            "otx",
          ],
          providers_failed: [],
        },
      }),
    ]);

    expect(screen.getByText("Unavailable Providers")).toBeInTheDocument();
    expect(screen.getByText("Google Safe Browsing unavailable.")).toBeInTheDocument();
    expect(screen.getByText("PhishTank unavailable.")).toBeInTheDocument();
    expect(screen.getByText("VirusTotal unavailable.")).toBeInTheDocument();
  });

  it("summarizes VirusTotal detections with a vendor count, not just Success", () => {
    renderUrl([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "malicious",
          label: "Malicious indicators detected",
          reasoning: [],
          providers_consulted: ["virustotal_url"],
          providers_unavailable: [],
          providers_failed: [],
        },
      }),
      makeResult({
        source: "virustotal_url",
        status: "success",
        data: { analysis_stats: { malicious: 5, suspicious: 2, harmless: 88 } },
      }),
    ]);

    expect(screen.getByText(/5\/95 vendors detected this URL as malicious/i)).toBeInTheDocument();
  });

  it("reuses the shared WHOIS section from Domain Investigation without duplicating logic", () => {
    renderUrl([
      makeResult({
        source: "whois",
        data: {
          registered: true,
          registrar: "MarkMonitor Inc.",
          creation_date: "1997-09-15T04:00:00Z",
          expiration_date: "2028-09-14T04:00:00Z",
          domain_statuses: [],
          name_servers: [],
          dnssec: "unsigned",
        },
      }),
    ]);

    expect(screen.getByText("Registration")).toBeInTheDocument();
    expect(screen.getByText("MarkMonitor Inc.")).toBeInTheDocument();
    expect(screen.getByText("1997")).toBeInTheDocument();
  });
});
