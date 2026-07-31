import type { InvestigationResult } from "@/types/investigation";

/**
 * `InvestigationResult.data` is `Record<string, unknown> | null` on the
 * wire - there is no per-module backend schema for most modules yet
 * (see ACCOUNT3_PARTC_DESIGN.md, section 1). These helpers let the
 * dedicated renderers (Reverse Image, File) read specific, verified
 * field names out of that blob defensively, so an unexpected shape
 * degrades to "not shown" rather than a crash.
 */

export function findResult(
  results: InvestigationResult[],
  source: string
): InvestigationResult | undefined {
  return results.find((result) => result.source === source);
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

export function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}
