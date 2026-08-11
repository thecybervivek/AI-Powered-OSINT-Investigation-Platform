import { ExternalLink, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import clsx from "clsx";

import type { InvestigationResult } from "@/types/investigation";
import { formatDate } from "@/utils/formatters";
import { asArray, asBoolean, asNumber, asRecord, asString, findResult } from "@/utils/evidenceData";
import { RiskBadge } from "@/components/Badge";
import { getEvidenceStatusMeta } from "../evidenceStatus";

interface EmailIntelligenceProps {
  results: InvestigationResult[];
}

/**
 * Built strictly from what email_service.py / account_presence.py
 * actually persist (read directly from those files, not assumed):
 *   disposable_email          -> email, domain, is_disposable
 *   mx_lookup                 -> domain, has_mx_records
 *   hibp                      -> breached, breach_count, breaches[] (name, breach_date,
 *                                 data_classes, is_sensitive), contains_sensitive_breach
 *   account_presence_summary  -> platforms[] (platform, category, status, confidence,
 *                                 evidence, provider_reason, profile_url, sources[]) -
 *                                 the deduplicated cross-provider view, preferred over
 *                                 reading holehe.results directly
 *   risk_assessment           -> risk_score, risk_level, contributing_evidence[]
 *
 * Section names are deliberately generic ("Account & Social Presence",
 * "Breach Intelligence") - "holehe" and "hibp" stay internal source
 * identifiers, never shown as a user-facing category. The raw
 * EvidenceList below this component still lists every source by name
 * (nothing hidden), it's just not the primary way this data is framed.
 */
export function EmailIntelligence({ results }: EmailIntelligenceProps) {
  const disposable = asRecord(findResult(results, "disposable_email")?.data);
  const mx = asRecord(findResult(results, "mx_lookup")?.data);
  const hibp = findResult(results, "hibp");
  const presenceSummary = asRecord(findResult(results, "account_presence_summary")?.data);
  const riskAssessment = asRecord(findResult(results, "risk_assessment")?.data);

  const platforms = asArray(presenceSummary?.platforms) as Record<string, unknown>[];

  return (
    <div className="space-y-6">
      <EmailOverviewSection disposable={disposable} mx={mx} />

      {platforms.length > 0 && <AccountPresenceSection platforms={platforms} />}

      {hibp && <BreachIntelligenceSection hibpResult={hibp} />}

      {riskAssessment && <RiskAssessmentSection assessment={riskAssessment} />}

      <ProviderStatusSection results={results} />
    </div>
  );
}

// ==========================================================
// 1. Email Overview
// ==========================================================

function EmailOverviewSection({
  disposable,
  mx,
}: {
  disposable: Record<string, unknown> | null;
  mx: Record<string, unknown> | null;
}) {
  if (!disposable && !mx) return null;

  const email = asString(disposable?.email);
  const domain = asString(disposable?.domain) ?? asString(mx?.domain);
  const isDisposable = asBoolean(disposable?.is_disposable);
  const hasMx = asBoolean(mx?.has_mx_records);

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-3 font-semibold text-slate-900 dark:text-white">Email Overview</h3>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
        {email && (
          <Field label="Email">
            <span className="break-all">{email}</span>
          </Field>
        )}
        {domain && <Field label="Domain">{domain}</Field>}
        {isDisposable !== null && (
          <Field label="Disposable Status">
            {isDisposable ? "Disposable address" : "Not a known disposable provider"}
          </Field>
        )}
        {hasMx !== null && (
          <Field label="MX Status">
            {hasMx ? "Domain accepts mail (MX records found)" : "No MX records found"}
          </Field>
        )}
      </dl>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-400">{label}</dt>
      <dd className="text-sm text-slate-700 dark:text-slate-300">{children}</dd>
    </div>
  );
}

// ==========================================================
// 2. Account & Social Presence
// ==========================================================

const PRESENCE_STATUS_LABEL: Record<string, string> = {
  confirmed: "Confirmed",
  not_found: "Not Found",
  unknown: "Unknown",
  blocked: "Blocked",
  rate_limited: "Rate Limited",
  failed: "Failed",
};

const PRESENCE_STATUS_BADGE: Record<string, string> = {
  confirmed: "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
  not_found: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  unknown: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
  blocked: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
  rate_limited: "bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300",
  failed: "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300",
};

function AccountPresenceSection({ platforms }: { platforms: Record<string, unknown>[] }) {
  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">
        Account &amp; Social Presence
      </h3>
      <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">
        Whether this address has a registered account on a given platform. This is
        discoverability, not a security finding on its own — it does not affect the risk score.
      </p>
      <div className="space-y-2">
        {platforms.map((platform) => {
          const name = asString(platform.platform) ?? "Unknown platform";
          const status = asString(platform.status) ?? "unknown";
          const confidence = asString(platform.confidence);
          const providerReason = asString(platform.provider_reason);
          const profileUrl = asString(platform.profile_url);
          const isConfirmed = status === "confirmed";

          return (
            <div
              key={name}
              className="rounded-md border border-slate-100 px-3 py-2 dark:border-slate-800"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-medium capitalize text-slate-900 dark:text-white">
                    {name}
                  </span>
                  <span
                    className={clsx(
                      "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
                      PRESENCE_STATUS_BADGE[status] ?? PRESENCE_STATUS_BADGE.unknown
                    )}
                  >
                    {PRESENCE_STATUS_LABEL[status] ?? "Unknown"}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
                  {confidence && <span className="capitalize">Confidence: {confidence}</span>}
                  {/* Only shown when the provider's own response legitimately
                      established this URL - never guessed from a username. */}
                  {isConfirmed && profileUrl && (
                    <a
                      href={profileUrl}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 text-brand-600 hover:underline"
                    >
                      Open Profile <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                  {isConfirmed && !profileUrl && (
                    <span className="italic">Profile: Not publicly available</span>
                  )}
                </div>
              </div>
              {providerReason && (
                <p className="mt-1 text-xs text-slate-400">{providerReason}</p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ==========================================================
// 3. Breach Intelligence
// ==========================================================
//
// Reuses this same investigation's own HIBP evidence rather than
// duplicating breach-checking logic - HIBP is already this platform's
// breach source for a single email (a separate, dedicated Breach
// Intelligence investigation type also exists for deeper multi-source
// lookups, but re-running/cross-linking that here is out of scope for
// this module's own summary).

function BreachIntelligenceSection({ hibpResult }: { hibpResult: InvestigationResult }) {
  const data = asRecord(hibpResult.data);

  if (hibpResult.status === "skipped") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Not checked — HaveIBeenPwned is not configured for this deployment. This does not
          mean no breach was found.
        </p>
      </div>
    );
  }

  if (hibpResult.status === "failed" || hibpResult.status === "rate_limited") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {hibpResult.status === "rate_limited"
            ? "HaveIBeenPwned rate-limited this check — breach status is unknown, not confirmed clean."
            : "The breach-history check did not complete — breach status is unknown, not confirmed clean."}
        </p>
      </div>
    );
  }

  const breaches = asArray(data?.breaches) as Record<string, unknown>[];
  const breached = asBoolean(data?.breached);

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>

      {!breached || breaches.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No known breaches found for this address. This reflects HaveIBeenPwned's records at the
          time of the check, not a guarantee the address was never exposed.
        </p>
      ) : (
        <div className="mt-2 space-y-3">
          <p className="text-xs font-medium text-red-600 dark:text-red-400">
            Breach Found — {breaches.length} record{breaches.length === 1 ? "" : "s"}
          </p>
          {breaches.map((breach, index) => {
            const name = asString(breach.name) ?? "Unnamed breach";
            const date = asString(breach.breach_date);
            const dataClasses = asArray(breach.data_classes) as string[];
            const passwordExposed = dataClasses.some((c) => c.toLowerCase().includes("password"));
            const sensitiveExposure = asBoolean(breach.is_sensitive);

            return (
              <div
                key={`${name}-${index}`}
                className="rounded-md border border-slate-100 p-3 dark:border-slate-800"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-slate-900 dark:text-white">{name}</span>
                  {date && <span className="text-xs text-slate-400">{formatDate(date)}</span>}
                </div>

                {dataClasses.length > 0 && (
                  <div className="mt-2">
                    <p className="text-xs uppercase tracking-wide text-slate-400">Exposed</p>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {dataClasses.map((category) => (
                        <span
                          key={category}
                          className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                        >
                          {category}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
                  <span
                    className={clsx(
                      "font-medium",
                      passwordExposed
                        ? "text-red-600 dark:text-red-400"
                        : "text-slate-500 dark:text-slate-400"
                    )}
                  >
                    Password exposure: {passwordExposed ? "Yes" : "No"}
                  </span>
                  {sensitiveExposure !== null && (
                    <span
                      className={clsx(
                        "font-medium",
                        sensitiveExposure
                          ? "text-red-600 dark:text-red-400"
                          : "text-slate-500 dark:text-slate-400"
                      )}
                    >
                      Sensitive data exposure: {sensitiveExposure ? "Yes" : "No"}
                    </span>
                  )}
                </div>

                <p className="mt-2 text-xs text-slate-400">
                  Source: HaveIBeenPwned —{" "}
                  <a
                    href="https://haveibeenpwned.com/"
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-brand-600 hover:underline"
                  >
                    View source <ExternalLink className="h-3 w-3" />
                  </a>
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ==========================================================
// 4. Risk Assessment
// ==========================================================

const RISK_ICONS: Record<string, typeof ShieldCheck> = {
  low: ShieldCheck,
  medium: ShieldQuestion,
  high: ShieldAlert,
  critical: ShieldAlert,
};

function RiskAssessmentSection({ assessment }: { assessment: Record<string, unknown> }) {
  const score = asNumber(assessment.risk_score);
  const level = asString(assessment.risk_level) as "low" | "medium" | "high" | "critical" | null;
  const evidence = asArray(assessment.contributing_evidence) as string[];
  const Icon = (level && RISK_ICONS[level]) || ShieldQuestion;

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-slate-900 dark:text-white">Risk Assessment</h3>
        <RiskBadge level={level} />
      </div>

      <div className="mt-2 flex items-center gap-2">
        <Icon className="h-4 w-4 text-slate-400" />
        <span className="text-lg font-semibold text-slate-900 dark:text-white">
          {score !== null ? `${score}/100` : "—"}
        </span>
      </div>

      <div className="mt-3">
        <p className="text-xs uppercase tracking-wide text-slate-400">Contributing evidence</p>
        {evidence.length > 0 ? (
          <ul className="mt-1 list-inside list-disc space-y-1 text-sm text-slate-600 dark:text-slate-400">
            {evidence.map((note, index) => (
              <li key={index}>{note}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            No breach or security evidence contributed to this score.
          </p>
        )}
        <p className="mt-2 text-xs text-slate-400">
          Account presence: not included in this score — see Account &amp; Social Presence above.
        </p>
      </div>
    </div>
  );
}

// ==========================================================
// 5. Provider / Evidence Status
// ==========================================================
//
// A compact per-source status line, distinct from the full raw
// EvidenceList below this component (which also shows each source's
// full data payload) - this is just the at-a-glance status column
// requested alongside the other 4 sections.

const INTERNAL_ONLY_SOURCES = new Set(["risk_assessment", "account_presence_summary"]);

const SOURCE_DISPLAY_NAME: Record<string, string> = {
  holehe: "Account & Social Presence",
  hibp: "HaveIBeenPwned",
  emailrep: "EmailRep",
  gravatar: "Gravatar",
  mx_lookup: "MX / Domain",
  disposable_email: "Disposable Address Check",
  google_intelligence: "Google Intelligence",
};

function ProviderStatusSection({ results }: { results: InvestigationResult[] }) {
  const visible = results.filter((r) => !INTERNAL_ONLY_SOURCES.has(r.source));

  if (visible.length === 0) return null;

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-3 font-semibold text-slate-900 dark:text-white">Provider Status</h3>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {visible.map((result) => {
          const meta = getEvidenceStatusMeta(result.status);
          return (
            <div
              key={result.source}
              className="flex items-center justify-between rounded-md border border-slate-100 px-3 py-1.5 text-sm dark:border-slate-800"
            >
              <span className="text-slate-700 dark:text-slate-300">
                {SOURCE_DISPLAY_NAME[result.source] ?? result.source}
              </span>
              <span
                className={clsx(
                  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium",
                  meta.badgeClassName
                )}
              >
                {meta.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
