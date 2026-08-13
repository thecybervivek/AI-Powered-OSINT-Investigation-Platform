import { CheckCircle2, ExternalLink, HelpCircle, ShieldAlert, ShieldCheck, ShieldQuestion, XCircle } from "lucide-react";
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
 * Built strictly from what email_service.py / integrations/email/
 * actually persist (read directly from those files, not assumed):
 *
 *   disposable_email          -> email, domain, is_disposable
 *   mx_lookup                 -> domain, has_mx_records
 *   hibp                      -> breached, breach_count, breaches[] (name, breach_date,
 *                                 data_classes, is_sensitive), contains_sensitive_breach
 *   account_presence_summary  -> the cross-provider deduplicated view built by
 *                                 integrations/email/normalization.py: confirmed_accounts[],
 *                                 not_found_platforms[], unable_to_verify_platforms[],
 *                                 providers_consulted[] - same architectural pattern as
 *                                 Username's username_normalization result.
 *   risk_assessment            -> risk_score, risk_level, contributing_evidence[]
 *
 * Section names are deliberately generic ("Account & Social Presence",
 * "Breach Intelligence") - "account_presence" and "hibp" stay internal
 * source identifiers, never shown as a user-facing category. The raw
 * EvidenceList below this component still lists every source by name
 * (nothing hidden), it's just not the primary way this data is framed.
 */
export function EmailIntelligence({ results }: EmailIntelligenceProps) {
  const disposable = asRecord(findResult(results, "disposable_email")?.data);
  const mx = asRecord(findResult(results, "mx_lookup")?.data);
  const hibp = findResult(results, "hibp");
  const presenceSummary = asRecord(findResult(results, "account_presence_summary")?.data);
  const riskAssessment = asRecord(findResult(results, "risk_assessment")?.data);

  return (
    <div className="space-y-6">
      <EmailOverviewSection disposable={disposable} mx={mx} />

      {presenceSummary && <AccountPresenceSection summary={presenceSummary} />}

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
//    (Confirmed / Not Found / Unable to Verify - same visual
//    pattern as UsernameIntelligence.tsx)
// ==========================================================

interface PresenceFinding {
  platform: string;
  category: string | null;
  profile_url: string | null;
  status: string;
  confidence: string;
  providers: string[];
  provider_reason: string | null;
}

function asFindingArray(value: unknown): PresenceFinding[] {
  if (!Array.isArray(value)) return [];

  return value
    .map((entry) => {
      const record = asRecord(entry);
      if (!record) return null;

      const platform = asString(record.platform);
      if (!platform) return null;

      return {
        platform,
        category: asString(record.category),
        profile_url: asString(record.profile_url),
        status: asString(record.status) ?? "unknown",
        confidence: asString(record.confidence) ?? "low",
        providers: Array.isArray(record.providers)
          ? (record.providers as unknown[]).map(String)
          : [],
        provider_reason: asString(record.provider_reason),
      };
    })
    .filter((f): f is PresenceFinding => f !== null);
}

function AccountPresenceSection({ summary }: { summary: Record<string, unknown> }) {
  const confirmed = asFindingArray(summary.confirmed_accounts);
  const notFound = asFindingArray(summary.not_found_platforms);
  const unableToVerify = asFindingArray(summary.unable_to_verify_platforms);
  const providers = Array.isArray(summary.providers_consulted)
    ? (summary.providers_consulted as unknown[]).map(String)
    : [];

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">
        Account &amp; Social Presence
      </h3>
      <p className="mb-4 text-xs text-slate-500 dark:text-slate-400">
        {confirmed.length} confirmed · {notFound.length} confidently not found ·{" "}
        {unableToVerify.length} unable to verify
        {providers.length > 0 && <> ({providers.join(", ")})</>}. This is discoverability, not a
        security finding on its own — it does not affect the risk score.
      </p>

      <div className="space-y-5">
        <PresenceGroup
          title="Confirmed Accounts"
          icon={CheckCircle2}
          tone="confirmed"
          findings={confirmed}
          emptyText="No confirmed accounts."
        />
        <PresenceGroup
          title="Not Found"
          icon={XCircle}
          tone="not_found"
          findings={notFound}
          emptyText="No platforms confidently verified as absent."
        />
        <PresenceGroup
          title="Unable to Verify"
          icon={HelpCircle}
          tone="unknown"
          findings={unableToVerify}
          emptyText="Nothing left unverified."
        />
      </div>
    </div>
  );
}

type Tone = "confirmed" | "not_found" | "unknown";

const GROUP_ICON_TONES: Record<Tone, string> = {
  confirmed: "text-green-600 dark:text-green-400",
  not_found: "text-slate-400 dark:text-slate-500",
  unknown: "text-amber-500 dark:text-amber-400",
};

function PresenceGroup({
  title,
  icon: Icon,
  tone,
  findings,
  emptyText,
}: {
  title: string;
  icon: typeof CheckCircle2;
  tone: Tone;
  findings: PresenceFinding[];
  emptyText: string;
}) {
  return (
    <div>
      <h4 className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
        <Icon className={clsx("h-4 w-4", GROUP_ICON_TONES[tone])} />
        {title} ({findings.length})
      </h4>

      {findings.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">{emptyText}</p>
      ) : (
        <div className="space-y-2">
          {findings.map((finding) => (
            <div
              key={finding.platform}
              className="rounded-md border border-slate-100 px-3 py-2 dark:border-slate-800"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-medium capitalize text-slate-900 dark:text-white">
                    {finding.platform.replace(/_/g, " ")}
                  </span>
                  {finding.status === "conflict" && (
                    <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">
                      Conflict
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
                  <span className="capitalize">Confidence: {finding.confidence}</span>
                  {finding.providers.length > 0 && <span>{finding.providers.join(", ")}</span>}
                  {tone === "confirmed" && finding.profile_url && (
                    <a
                      href={finding.profile_url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-center gap-1 text-brand-600 hover:underline"
                    >
                      Open Profile <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>
              </div>
              {finding.provider_reason && (
                <p className="mt-1 text-xs text-slate-400">{finding.provider_reason}</p>
              )}
            </div>
          ))}
        </div>
      )}
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
          Not checked — provider unavailable/configuration missing. This does not mean no breach
          was found.
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
  account_presence: "Account & Social Presence",
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
