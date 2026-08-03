import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { DomainIntelligence } from "@/components/investigation-result/modules/DomainIntelligence";
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

function renderDomain(results: InvestigationResult[]) {
  return render(
    <MemoryRouter>
      <DomainIntelligence results={results} />
    </MemoryRouter>
  );
}

describe("DomainIntelligence", () => {
  it("shows the exact required assessment label text, never a numeric score", () => {
    renderDomain([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "no_malicious_evidence_detected",
          label: "No malicious evidence detected",
          reasoning: [],
          providers_consulted: ["shodan"],
          providers_unavailable: [],
          providers_failed: [],
        },
      }),
    ]);

    expect(screen.getByText("No malicious evidence detected")).toBeInTheDocument();
    expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^safe$/i)).not.toBeInTheDocument();
  });

  it("shows Certificate Transparency's friendly unavailable message on failure, not the raw HTTP error", () => {
    renderDomain([
      makeResult({
        source: "certificate_transparency",
        status: "failed",
        data: {},
        error_message: "Certificate Transparency temporarily unavailable.",
      }),
    ]);

    expect(
      screen.getByText("Certificate Transparency temporarily unavailable.")
    ).toBeInTheDocument();
    expect(screen.queryByText(/HTTP 502/)).not.toBeInTheDocument();
  });

  it("renders IP Intelligence as a compact table, not one card per IP", () => {
    renderDomain([
      makeResult({
        source: "ip_intelligence_summary",
        data: {
          public_ip_count: 2,
          non_public_ip_count: 0,
          ips: [
            {
              ip_address: "142.250.1.1",
              asn: { status: "success", data: { asn: "AS15169", asn_name: "Google LLC" } },
              geolocation: { status: "success", data: { country: "US" } },
              reverse_dns: { status: "not_found", data: null },
            },
            {
              ip_address: "142.250.1.2",
              asn: { status: "success", data: { asn: "AS15169", asn_name: "Google LLC" } },
              geolocation: { status: "success", data: { country: "US" } },
              reverse_dns: { status: "not_found", data: null },
            },
          ],
        },
      }),
    ]);

    // A real <table>, not a repeated-card layout.
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.getAllByText("AS15169 (Google LLC)")).toHaveLength(2);
    expect(screen.getAllByText("None")).toHaveLength(2); // reverse DNS column
  });

  it("shows one shared IPv6-unsupported note instead of a skipped card per address", () => {
    renderDomain([
      makeResult({
        source: "ip_intelligence_summary",
        data: {
          public_ip_count: 2,
          non_public_ip_count: 0,
          ips: [
            {
              ip_address: "2606:4700:4700::1111",
              asn: { status: "skipped" },
              geolocation: { status: "success", data: { country: "US" } },
              reverse_dns: { status: "not_found", data: null },
            },
            {
              ip_address: "2606:4700:4700::1001",
              asn: { status: "skipped" },
              geolocation: { status: "success", data: { country: "US" } },
              reverse_dns: { status: "not_found", data: null },
            },
          ],
        },
      }),
    ]);

    expect(
      screen.getAllByText("IPv6 ASN lookup is not supported by the current provider.")
    ).toHaveLength(1);
    expect(screen.getAllByText("Not supported")).toHaveLength(2);
  });

  it("lists unavailable threat intelligence providers without marking anything failed", () => {
    renderDomain([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "threat_assessment_incomplete",
          label: "Threat assessment incomplete",
          reasoning: [],
          providers_consulted: [],
          providers_unavailable: ["shodan", "censys", "greynoise", "otx"],
          providers_failed: [],
        },
      }),
    ]);

    expect(screen.getByText("Unavailable Providers")).toBeInTheDocument();
    expect(screen.getByText("Shodan")).toBeInTheDocument();
    expect(screen.getByText("Censys")).toBeInTheDocument();
    expect(screen.getByText("GreyNoise")).toBeInTheDocument();
    expect(screen.getByText("OTX")).toBeInTheDocument();
  });

  it("summarizes a consulted threat provider's actual findings, not just its status", () => {
    renderDomain([
      makeResult({
        source: "threat_assessment",
        data: {
          state: "no_malicious_evidence_detected",
          label: "No malicious evidence detected",
          reasoning: [],
          providers_consulted: ["otx"],
          providers_unavailable: [],
          providers_failed: [],
        },
      }),
      makeResult({
        source: "otx:1.2.3.4",
        status: "success",
        data: { pulse_count: 0 },
      }),
    ]);

    expect(
      screen.getByText(/not referenced in any community threat pulses/i)
    ).toBeInTheDocument();
  });

  it("shows a concise WHOIS registration line with extracted years, not raw ISO timestamps", () => {
    renderDomain([
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

    expect(screen.getByText("MarkMonitor Inc.")).toBeInTheDocument();
    expect(screen.getByText("1997")).toBeInTheDocument();
    expect(screen.getByText("2028")).toBeInTheDocument();
  });

  it("shows a concise TLS validity line with month/year, not a raw ISO timestamp", () => {
    renderDomain([
      makeResult({
        source: "ssl_certificate",
        data: {
          certificate_valid: true,
          is_expired: false,
          not_before: "2026-06-01T00:00:00Z",
          not_after: "2026-09-01T00:00:00Z",
          subject: { commonName: "example.com" },
          issuer: { organizationName: "Google Trust Services" },
          subject_alt_names: [],
        },
      }),
    ]);

    expect(screen.getByText(/Valid until Sep 2026/i)).toBeInTheDocument();
    expect(screen.getByText(/issued by Google Trust Services/i)).toBeInTheDocument();
  });
});
