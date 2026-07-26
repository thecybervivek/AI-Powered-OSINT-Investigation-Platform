import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { RiskBadge, StatusBadge } from "@/components/Badge";

describe("RiskBadge", () => {
  it("renders the risk level label", () => {
    render(<RiskBadge level="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("renders 'Unknown' when level is null", () => {
    render(<RiskBadge level={null} />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("renders the status label", () => {
    render(<StatusBadge status="completed" />);
    expect(screen.getByText("completed")).toBeInTheDocument();
  });

  it("renders unrecognized statuses without crashing", () => {
    render(<StatusBadge status="some_new_status" />);
    expect(screen.getByText("some_new_status")).toBeInTheDocument();
  });
});
