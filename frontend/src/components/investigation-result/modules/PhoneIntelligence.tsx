import { ExternalLink, Globe2, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import clsx from "clsx";

import type { InvestigationResult } from "@/types/investigation";
import { asArray, asBoolean, asNumber, asRecord, asString, findResult } from "@/utils/evidenceData";
import { RiskBadge } from "@/components/Badge";
import { getEvidenceStatusMeta } from "../evidenceStatus";

interface PhoneIntelligenceProps {
  results: InvestigationResult[];
}

/**
 * Built strictly from what phone_service.py actually persists:
 *
 *   phone_overview            -> normalized_e164, country, number_type,
 *                                 formats, timezones, assumed_country,
 *                                 providers_consulted (dedup across
 *                                 phone_validation + numverify)
 *   phone_validation           -> raw libphonenumber result
 *   numverify                  -> live carrier/line-type lookup
 *   phone_reputation            -> spam/scam/fraud/abuse flags (optional)
 *   phone_breach                -> DeHashed phone-number exposure search (optional)
 *   phone_public_intelligence  -> legitimate public references (optional)
 *   risk_assessment             -> risk_score, risk_level, contributing_evidence[]
 *
 * Architecture mirrors EmailIntelligence.tsx: Overview -> Carrier &
 * Network -> Reputation -> Breach -> Public Intelligence -> Risk
 * Assessment -> Provider Status. A missing/SKIPPED optional source is
 * always rendered as "Not checked" - never collapsed into "safe".
 */
export function PhoneIntelligence({ results }: PhoneIntelligenceProps) {
  const overview = asRecord(findResult(results, "phone_overview")?.data);
  const numverify = findResult(results, "numverify");
  const reputation = findResult(results, "phone_reputation");
  const breach = findResult(results, "phone_breach");
  const publicIntel = findResult(results, "phone_public_intelligence");
  const riskAssessment = asRecord(findResult(results, "risk_assessment")?.data);

  if (!overview) return null;

  return (
    <div className="space-y-6">
      <PhoneOverviewSection overview={overview} />

      <CarrierNetworkSection numverifyResult={numverify} />

      <ReputationIntelligenceSection reputationResult={reputation} />

      <BreachIntelligenceSection breachResult={breach} />

      <PublicIntelligenceSection publicResult={publicIntel} />

      {riskAssessment && <RiskAssessmentSection assessment={riskAssessment} />}

      <ProviderStatusSection results={results} />
    </div>
  );
}

// ==========================================================
// 1. Phone Overview
// ==========================================================

function PhoneOverviewSection({ overview }: { overview: Record<string, unknown> }) {
  const rawInput = asString(overview.raw_input);
  const normalized = asString(overview.normalized_e164);
  const country = asString(overview.country);
  const numberType = asString(overview.number_type);
  const internationalFormat = asString(overview.international_format);
  const nationalFormat = asString(overview.national_format);
  const timezones = asArray(overview.timezones) as string[];
  const assumedCountry = asString(overview.assumed_country);
  const isValid = asBoolean(overview.is_valid);
  const isPossible = asBoolean(overview.is_possible);

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Phone Overview</h3>
      {assumedCountry && (
        <p className="mb-3 text-xs text-slate-500 dark:text-slate-400">
          No country code was given, so this was resolved as an {assumedCountry} number.
          Missing a country code is a formatting detail, not a risk signal.
        </p>
      )}
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
        {rawInput && <Field label="Original Input">{rawInput}</Field>}
        {normalized && <Field label="Normalized (E.164)">{normalized}</Field>}
        {country && <Field label="Country">{country}</Field>}
        {numberType && <Field label="Number Type">{numberType.replace(/_/g, " ")}</Field>}
        {internationalFormat && (
          <Field label="International Format">{internationalFormat}</Field>
        )}
        {nationalFormat && <Field label="National Format">{nationalFormat}</Field>}
        {timezones.length > 0 && <Field label="Timezone(s)">{timezones.join(", ")}</Field>}
        {isValid !== null && (
          <Field label="Validation">
            {isValid ? "Valid" : isPossible ? "Possible, not confirmed valid" : "Invalid"}
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
// 2. Carrier & Network Intelligence (NumVerify)
// ==========================================================

function CarrierNetworkSection({
  numverifyResult,
}: {
  numverifyResult: InvestigationResult | undefined;
}) {
  if (!numverifyResult) return null;

  if (numverifyResult.status === "skipped") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Carrier &amp; Network</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Numverify — Skipped. API key not configured.
        </p>
      </div>
    );
  }

  if (numverifyResult.status === "failed" || numverifyResult.status === "rate_limited") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Carrier &amp; Network</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {numverifyResult.status === "rate_limited"
            ? "NumVerify rate-limited this check — carrier data is unavailable, not absent."
            : "The carrier lookup did not complete — carrier data is unavailable, not absent."}
        </p>
      </div>
    );
  }

  const data = asRecord(numverifyResult.data);
  const carrier = asString(data?.carrier);
  const lineType = asString(data?.line_type);
  const countryName = asString(data?.country_name);
  const countryPrefix = asString(data?.country_prefix);
  const location = asString(data?.location);

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-3 font-semibold text-slate-900 dark:text-white">Carrier &amp; Network</h3>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
        {carrier && <Field label="Carrier">{carrier}</Field>}
        {lineType && <Field label="Line Type">{lineType}</Field>}
        {countryName && <Field label="Country">{countryName}</Field>}
        {countryPrefix && <Field label="Dialing Code">+{countryPrefix}</Field>}
        {location && <Field label="Region">{location}</Field>}
      </dl>
      <p className="mt-3 text-xs text-slate-400">Source: NumVerify</p>
    </div>
  );
}

// ==========================================================
// 3. Reputation Intelligence
// ==========================================================

function ReputationIntelligenceSection({
  reputationResult,
}: {
  reputationResult: InvestigationResult | undefined;
}) {
  if (!reputationResult) return null;

  if (reputationResult.status !== "success") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Reputation Intelligence</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Not checked — no reputation provider is configured for this deployment. This does not
          mean the number is safe.
        </p>
      </div>
    );
  }

  const data = asRecord(reputationResult.data) ?? {};
  const flags = ["spam", "scam", "fraud", "abuse", "malicious_activity", "suspicious_activity"]
    .filter((key) => asBoolean(data[key]))
    .map((key) => key.replace(/_/g, " "));

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Reputation Intelligence</h3>
      {flags.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No spam, scam, fraud, or abuse signals reported by this provider.
        </p>
      ) : (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {flags.map((flag) => (
            <span
              key={flag}
              className="rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium capitalize text-red-700 dark:bg-red-900/40 dark:text-red-300"
            >
              {flag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ==========================================================
// 4. Breach Intelligence
// ==========================================================

function BreachIntelligenceSection({
  breachResult,
}: {
  breachResult: InvestigationResult | undefined;
}) {
  if (!breachResult) return null;

  if (breachResult.status === "skipped") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Not checked — provider unavailable/not configured.
        </p>
      </div>
    );
  }

  if (breachResult.status === "failed" || breachResult.status === "rate_limited") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {breachResult.status === "rate_limited"
            ? "The breach provider rate-limited this check — breach status is unknown, not confirmed clean."
            : "The breach check did not complete — breach status is unknown, not confirmed clean."}
        </p>
      </div>
    );
  }

  const data = asRecord(breachResult.data) ?? {};
  const totalEntries = asNumber(data.total_entries) ?? 0;
  const databases = asArray(data.breached_databases) as string[];
  const hasPlaintext = asBoolean(data.has_plaintext_password_exposure);
  const hasHashed = asBoolean(data.has_hashed_password_exposure);

  if (totalEntries === 0) {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No known breach exposure found for this number at the time of the check.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 font-semibold text-slate-900 dark:text-white">Breach Intelligence</h3>
      <p className="text-xs font-medium text-red-600 dark:text-red-400">
        Breach Found — {totalEntries} record{totalEntries === 1 ? "" : "s"}
      </p>
      {databases.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {databases.map((db) => (
            <span
              key={db}
              className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300"
            >
              {db}
            </span>
          ))}
        </div>
      )}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <span
          className={clsx(
            "font-medium",
            hasPlaintext ? "text-red-600 dark:text-red-400" : "text-slate-500 dark:text-slate-400"
          )}
        >
          Plaintext password exposure: {hasPlaintext ? "Yes" : "No"}
        </span>
        <span
          className={clsx(
            "font-medium",
            hasHashed ? "text-orange-600 dark:text-orange-400" : "text-slate-500 dark:text-slate-400"
          )}
        >
          Hashed password exposure: {hasHashed ? "Yes" : "No"}
        </span>
      </div>
    </div>
  );
}

// ==========================================================
// 5. Public Intelligence
// ==========================================================

function PublicIntelligenceSection({
  publicResult,
}: {
  publicResult: InvestigationResult | undefined;
}) {
  if (!publicResult) return null;

  if (publicResult.status === "skipped") {
    return (
      <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
        <h3 className="mb-1 flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
          <Globe2 className="h-4 w-4 text-slate-400" />
          Public Intelligence
        </h3>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Not checked — no public-search provider configured for this deployment.
        </p>
      </div>
    );
  }

  const data = asRecord(publicResult.data) ?? {};
  const references = asArray(data.public_references) as Record<string, unknown>[];

  return (
    <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
      <h3 className="mb-1 flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
        <Globe2 className="h-4 w-4 text-slate-400" />
        Public Intelligence
      </h3>
      {references.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No legitimately accessible public references found.
        </p>
      ) : (
        <ul className="mt-2 space-y-1.5">
          {references.map((ref, index) => {
            const url = asString(ref.url);
            const label = asString(ref.title) ?? url ?? "Public reference";
            return (
              <li key={index} className="text-sm">
                {url ? (
                  <a
                    href={url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="inline-flex items-center gap-1 text-brand-600 hover:underline"
                  >
                    {label} <ExternalLink className="h-3 w-3" />
                  </a>
                ) : (
                  <span className="text-slate-600 dark:text-slate-300">{label}</span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

// ==========================================================
// 6. Risk Assessment
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
            No confirmed security or reputation evidence contributed to this score. Validity,
            carrier, country, and discoverability are never scored on their own.
          </p>
        )}
      </div>
    </div>
  );
}

// ==========================================================
// 7. Provider Status
// ==========================================================

const INTERNAL_ONLY_SOURCES = new Set(["risk_assessment", "phone_overview"]);

const SOURCE_DISPLAY_NAME: Record<string, string> = {
  phone_validation: "Phone Validation",
  numverify: "NumVerify (Carrier & Network)",
  phone_reputation: "Reputation Provider",
  phone_breach: "Breach Provider",
  phone_public_intelligence: "Public Intelligence",
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
