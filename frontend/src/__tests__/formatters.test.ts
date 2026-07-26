import { describe, expect, it } from "vitest";
import { formatBytes, formatRiskScore, truncate } from "@/utils/formatters";

describe("formatBytes", () => {
  it("formats zero bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("formats kilobytes", () => {
    expect(formatBytes(2048)).toBe("2.0 KB");
  });

  it("formats megabytes", () => {
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
  });
});

describe("formatRiskScore", () => {
  it("returns em dash for null", () => {
    expect(formatRiskScore(null)).toBe("—");
  });

  it("formats a numeric score out of 100", () => {
    expect(formatRiskScore(72.456)).toBe("72.5/100");
  });
});

describe("truncate", () => {
  it("leaves short strings unchanged", () => {
    expect(truncate("short", 10)).toBe("short");
  });

  it("truncates long strings with an ellipsis", () => {
    expect(truncate("a very long string indeed", 10)).toBe("a very lon…");
  });
});
