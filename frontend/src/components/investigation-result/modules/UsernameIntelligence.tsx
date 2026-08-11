import { CheckCircle2, XCircle, HelpCircle, Link as LinkIcon } from "lucide-react";
import clsx from "clsx";

import type { InvestigationResult } from "@/types/investigation";
import { asRecord, asString, findResult } from "@/utils/evidenceData";

interface UsernameIntelligenceProps {
  results: InvestigationResult[];
}

/**
 * Built strictly from what username_service.py actually persists:
 *
 *   username_normalization -> the cross-engine deduplicated view
 *                              (confirmed_profiles / not_found_platforms /
 *                              unable_to_verify_platforms), built by
 *                              integrations/username/normalization.py.
 *
 * Username Intelligence is profile-discovery, not threat scoring - so
 * unlike Domain/URL's AssessmentBanner, there is no state/label/risk
 * concept here at all. This intentionally never renders a numeric
 * Risk Score or Risk Level; see InvestigationDetailPage's
 * hasEvidenceBackedAssessment list.
 */
export function UsernameIntelligence({ results }: UsernameIntelligenceProps) {
  const normalization = asRecord(findResult(results, "username_normalization")?.data);

  if (!normalization) return null;

  const confirmed = asFindingArray(normalization.confirmed_profiles);
  const notFound = asFindingArray(normalization.not_found_platforms);
  const unableToVerify = asFindingArray(normalization.unable_to_verify_platforms);
  const providers = Array.isArray(normalization.providers_consulted)
    ? (normalization.providers_consulted as unknown[]).map(String)
    : [];

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300">
        Checked across {providers.length} engine{providers.length === 1 ? "" : "s"}
        {providers.length > 0 && <> ({providers.join(", ")})</>}. Username matches show
        public-profile discoverability only - they are not identity confirmation.
      </div>

      <FindingSection
        title="Confirmed Profiles"
        icon={CheckCircle2}
        tone="confirmed"
        findings={confirmed}
        emptyText="No confirmed profiles."
      />

      <FindingSection
        title="Not Found"
        icon={XCircle}
        tone="not_found"
        findings={notFound}
        emptyText="No platforms confidently verified as absent."
      />

      <FindingSection
        title="Unable to Verify"
        icon={HelpCircle}
        tone="unknown"
        findings={unableToVerify}
        emptyText="Nothing left unverified."
      />
    </div>
  );
}

// ==========================================================
// Section + finding card
// ==========================================================

type Tone = "confirmed" | "not_found" | "unknown";

const SECTION_ICON_TONES: Record<Tone, string> = {
  confirmed: "text-green-600 dark:text-green-400",
  not_found: "text-slate-400 dark:text-slate-500",
  unknown: "text-amber-500 dark:text-amber-400",
};

const CARD_TONES: Record<Tone, string> = {
  confirmed:
    "border-green-200 bg-green-50/50 dark:border-green-900/40 dark:bg-green-950/10",
  not_found: "border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-800/40",
  unknown:
    "border-amber-200 bg-amber-50/50 dark:border-amber-900/40 dark:bg-amber-950/10",
};

interface Finding {
  platform: string;
  category: string | null;
  profile_url: string | null;
  status: string;
  confidence: string;
  providers: string[];
}

function asFindingArray(value: unknown): Finding[] {
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
      };
    })
    .filter((f): f is Finding => f !== null);
}

function FindingSection({
  title,
  icon: Icon,
  tone,
  findings,
  emptyText,
}: {
  title: string;
  icon: typeof CheckCircle2;
  tone: Tone;
  findings: Finding[];
  emptyText: string;
}) {
  return (
    <div>
      <h3 className="mb-3 flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
        <Icon className={clsx("h-4 w-4", SECTION_ICON_TONES[tone])} />
        {title} ({findings.length})
      </h3>

      {findings.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">{emptyText}</p>
      ) : (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {findings.map((finding) => (
            <div
              key={finding.platform}
              className={clsx("rounded-lg border p-3", CARD_TONES[tone])}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-slate-900 dark:text-white">
                  {finding.platform}
                </span>
                {finding.status === "conflict" && (
                  <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">
                    Conflict
                  </span>
                )}
              </div>

              {finding.profile_url && tone === "confirmed" && (
                <a
                  href={finding.profile_url}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1 flex items-center gap-1 text-xs text-brand-600 hover:underline dark:text-brand-400"
                >
                  <LinkIcon className="h-3 w-3" />
                  View profile
                </a>
              )}

              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Confidence: {finding.confidence} · {finding.providers.join(", ")}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
