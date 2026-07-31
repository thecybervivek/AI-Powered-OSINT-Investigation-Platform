import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

import { EvidenceList } from "@/components/investigation-result/EvidenceList";
import type {
  InvestigationResult,
  ModuleResultStatus,
} from "@/types/investigation";

function makeResult(
  overrides: Partial<InvestigationResult>
): InvestigationResult {
  return {
    id: overrides.id ?? "result-1",
    source: "example_provider",
    status: "success",
    data: { finding: "value" },
    error_message: null,
    latency_ms: 842,
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderList(results: InvestigationResult[]) {
  return render(
    <MemoryRouter>
      <EvidenceList results={results} />
    </MemoryRouter>
  );
}

describe("EvidenceList / EvidenceCard", () => {
  it("renders every evidence source with its source name and count", () => {
    renderList([
      makeResult({ id: "a", source: "email_rep", status: "success" }),
      makeResult({ id: "b", source: "hibp", status: "not_found" }),
    ]);

    expect(screen.getByText("Evidence (2 sources)")).toBeInTheDocument();
    expect(screen.getByText("email rep")).toBeInTheDocument();
    expect(screen.getByText("hibp")).toBeInTheDocument();
  });

  it("shows an explicit empty state when there are no results", () => {
    renderList([]);

    expect(
      screen.getByText(
        "No evidence sources recorded for this investigation."
      )
    ).toBeInTheDocument();
  });

  const cases: Array<{
    status: ModuleResultStatus;
    label: string;
  }> = [
    {
      status: "success",
      label: "Success",
    },
    {
      status: "not_found",
      label: "Not Found",
    },
    {
      status: "skipped",
      label: "Skipped",
    },
    {
      status: "failed",
      label: "Failed",
    },
    {
      status: "rate_limited",
      label: "Rate Limited",
    },
  ];

  it.each(cases)(
    "renders the $status status with its own distinct label",
    ({ status, label }) => {
      renderList([
        makeResult({
          status,
          error_message: null,
        }),
      ]);

      expect(screen.getByText(label)).toBeInTheDocument();
    }
  );

  it("does not treat NOT_FOUND, SKIPPED, or FAILED as a confirmed clean result", () => {
    renderList([
      makeResult({
        id: "a",
        status: "not_found",
        error_message: null,
      }),
      makeResult({
        id: "b",
        status: "skipped",
        error_message: null,
      }),
      makeResult({
        id: "c",
        status: "failed",
        error_message: null,
      }),
    ]);

    const bodyText = document.body.textContent ?? "";

    expect(bodyText).not.toMatch(/\bclean\b/i);
    expect(bodyText).not.toMatch(/no finding/i);

    expect(bodyText).toMatch(
      /does not confirm the target is safe elsewhere/i
    );

    expect(bodyText).toMatch(
      /whether the target has findings here is unknown/i
    );

    expect(bodyText).toMatch(
      /nothing was checked here/i
    );
  });

  it("does not show latency or raw data in the collapsed primary view", () => {
    renderList([
      makeResult({
        latency_ms: 4213,
        data: { secret_field: "xyz123" },
      }),
    ]);

    expect(screen.queryByText(/4213/)).not.toBeInTheDocument();
    expect(screen.queryByText(/xyz123/)).not.toBeInTheDocument();
  });

  it("reveals latency and raw data only inside Technical Details after expanding", async () => {
    const user = userEvent.setup();

    renderList([
      makeResult({
        latency_ms: 4213,
        data: { secret_field: "xyz123" },
      }),
    ]);

    await user.click(
      screen.getByRole("button", { name: /example provider/i })
    );

    expect(screen.getByText("4213ms")).toBeInTheDocument();
    expect(screen.getByText(/xyz123/)).toBeInTheDocument();
  });

  it("shows the provider's error message when present, and a neutral explanation for FAILED when it isn't", async () => {
    const user = userEvent.setup();

    renderList([
      makeResult({
        id: "with-error",
        source: "provider_a",
        status: "failed",
        error_message: "Provider unavailable / configuration missing",
      }),
      makeResult({
        id: "without-error",
        source: "provider_b",
        status: "failed",
        error_message: null,
      }),
    ]);

    expect(
      screen.getByText(
        "Provider unavailable / configuration missing"
      )
    ).toBeInTheDocument();

    expect(
      screen.getByText(/ran but encountered an error/i)
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: /provider a/i })
    );

    expect(screen.getByText("Provider error")).toBeInTheDocument();
  });

  it("shows a neutral, non-committal reason for SKIPPED that does not read as a finding", () => {
    renderList([
      makeResult({
        status: "skipped",
        error_message: null,
      }),
    ]);

    expect(
      screen.getByText(/did not run for this investigation/i)
    ).toBeInTheDocument();
  });
});