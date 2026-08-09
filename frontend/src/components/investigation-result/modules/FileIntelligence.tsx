import type { InvestigationResult } from "@/types/investigation";
import { formatBytes, formatDate } from "@/utils/formatters";
import { asBoolean, asNumber, asRecord, asString, findResult } from "@/utils/evidenceData";
import { AssessmentBanner } from "./DomainIntelligence";

interface FileIntelligenceProps {
  results: InvestigationResult[];
}

/**
 * Built strictly from what file_service.py actually writes into
 * InvestigationResult.data today (verified by reading that file
 * directly in this session):
 *   file_validation     -> declared_extension, detected_mime_type,
 *                           file_size_bytes, has_double_extension,
 *                           suspicious_extension, errors
 *   hash_analysis       -> md5, sha1, sha256, sha512
 *   metadata_extraction -> format, mode, width, height, exif, gps,
 *                           error, supported (image types); other
 *                           document types return their own fields
 *   timeline_analysis   -> filesystem_*_at, plus embedded_created /
 *                           embedded_modified when metadata has them
 *
 * Reputation-engine and YARA results (dynamic source names, run
 * per-file) are intentionally NOT hand-parsed here - their exact
 * per-engine shape wasn't verified against source in this session, so
 * summarizing them would risk misrepresenting a security verdict.
 * They still render in full via the generic EvidenceList below this
 * component - nothing is hidden, just not paraphrased.
 *
 * Note: the original uploaded filename is not available here. It's
 * only returned once, in the upload response - the GET investigation
 * endpoint this page uses does not expose it. See changelog.
 */
export function FileIntelligence({ results }: FileIntelligenceProps) {
  const validation = asRecord(findResult(results, "file_validation")?.data);
  const hashes = asRecord(findResult(results, "hash_analysis")?.data);
  const metadata = asRecord(findResult(results, "metadata_extraction")?.data);
  const timeline = asRecord(findResult(results, "timeline_analysis")?.data);
  const integrity = asRecord(findResult(results, "file_integrity")?.data);
  const assessment = asRecord(findResult(results, "threat_assessment")?.data);
  const virustotal = asRecord(findResult(results, "virustotal_file")?.data);

  return (
    <div className="space-y-6">
      {assessment && <AssessmentBanner assessment={assessment} />}

      {validation && (
        <Section title="File Overview">
          <FieldGrid
            fields={[
              ["Detected type", asString(validation.detected_mime_type) ?? "Unknown"],
              ["Declared extension", asString(validation.declared_extension) ?? "—"],
              [
                "File size",
                (() => {
                  const size = asNumber(validation.file_size_bytes);
                  return size !== null ? formatBytes(size) : "—";
                })(),
              ],
            ]}
          />
          {asBoolean(validation.suspicious_extension) && (
            <Callout>
              This file's extension was flagged as suspicious during
              validation.
            </Callout>
          )}
          {asBoolean(validation.has_double_extension) && (
            <Callout>
              This file has a double extension (e.g. "invoice.pdf.exe"),
              a pattern sometimes used to disguise executable content.
            </Callout>
          )}
        </Section>
      )}

      {hashes && (
        <Section title="Cryptographic Fingerprints">
          <FieldGrid
            mono
            fields={[
              ["MD5", asString(hashes.md5) ?? "—"],
              ["SHA-1", asString(hashes.sha1) ?? "—"],
              ["SHA-256", asString(hashes.sha256) ?? "—"],
              ["SHA-512", asString(hashes.sha512) ?? "—"],
            ]}
          />
        </Section>
      )}

      {metadata && (
        <Section title="Metadata">
          {metadata.error ? (
            <Callout>Metadata extraction failed: {asString(metadata.error)}</Callout>
          ) : metadata.supported === false ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Metadata extraction is not supported for this file type.
            </p>
          ) : (
            <FieldGrid
              fields={Object.entries(metadata)
                .filter(([key]) => !["error", "supported", "exif", "gps"].includes(key))
                .map(([key, value]) => [key, String(value)])}
            />
          )}
        </Section>
      )}

      {timeline && Object.keys(timeline).length > 0 && (
        <Section title="Timeline">
          <FieldGrid
            fields={Object.entries(timeline).map(([key, value]) => [
              key.replace(/_/g, " "),
              typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)
                ? formatDate(value)
                : String(value),
            ])}
          />
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Filesystem timestamps reflect when this server received the
            file, not necessarily when it was originally created.
            Embedded timestamps (if shown) come from the file's own
            metadata and are only as reliable as whatever last wrote
            them.
          </p>
        </Section>
      )}

      {integrity && (
        <Section title="File Structure">
          <FieldGrid
            fields={[
              [
                "Entropy",
                asNumber(integrity.entropy) !== null
                  ? `${integrity.entropy} bits/byte`
                  : "—",
              ],
              ["Packed/compressed indicator", asBoolean(integrity.high_entropy) ? "Yes" : "No"],
            ]}
          />
          {asBoolean(integrity.high_entropy) && (
            <Callout>
              This file's entropy is high enough to suggest it may be
              packed, compressed, or encrypted. This is a prompt to look
              closer, not itself a malicious indicator - legitimate
              compressed/encrypted files show the same signal.
            </Callout>
          )}
        </Section>
      )}

      <MalwareIntelligenceSection results={results} assessment={assessment} />

      {virustotal?.signature_info ? (
        <Section title="Digital Signature">
          <FieldGrid
            fields={Object.entries(asRecord(virustotal.signature_info) ?? {}).map(
              ([key, value]) => [key.replace(/_/g, " "), String(value)]
            )}
          />
        </Section>
      ) : (
        <Section title="Digital Signature">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Not checked - signature information is only available when
            VirusTotal is configured and has analyzed this file.
          </p>
        </Section>
      )}
    </div>
  );
}

// ==========================================================
// Malware Intelligence
// ==========================================================

const MALWARE_PROVIDER_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  malwarebazaar: "MalwareBazaar",
  hybrid_analysis: "Hybrid Analysis",
  otx: "OTX",
};

const MALWARE_SOURCE_NAMES: Record<string, string> = {
  virustotal: "virustotal_file",
  malwarebazaar: "malwarebazaar",
  hybrid_analysis: "hybrid_analysis",
  otx: "otx",
};

function summarizeMalwareProvider(
  key: string,
  result: InvestigationResult
): string {
  const data = asRecord(result.data);

  if (result.status === "not_found") {
    return "Not previously seen by this provider.";
  }

  if (!data) {
    return "Ran, no additional detail returned.";
  }

  if (key === "virustotal") {
    const stats = asRecord(data.analysis_stats);
    const malicious = (stats?.malicious as number) ?? 0;
    const total = stats
      ? Object.values(stats).reduce(
          (sum: number, v) => sum + (typeof v === "number" ? v : 0),
          0
        )
      : 0;

    return `${malicious} / ${total} detections`;
  }

  if (key === "malwarebazaar") {
    return asBoolean(data.known_to_malwarebazaar)
      ? `Known sample${asString(data.signature) ? ` (${data.signature})` : ""}.`
      : "Not a known sample.";
  }

  if (key === "hybrid_analysis") {
    const verdict = asString(data.verdict);
    return verdict ? `Verdict: ${verdict}.` : "Ran, no verdict returned.";
  }

  if (key === "otx") {
    const pulseCount = (data.pulse_count as number) ?? 0;
    return pulseCount > 0
      ? `Referenced in ${pulseCount} community threat pulse${
          pulseCount === 1 ? "" : "s"
        }.`
      : "Not referenced in any community threat pulses.";
  }

  return "Ran, no additional detail returned.";
}

function MalwareIntelligenceSection({
  results,
  assessment,
}: {
  results: InvestigationResult[];
  assessment: Record<string, unknown> | null;
}) {
  const yara = asRecord(findResult(results, "yara_scan")?.data);
  const yaraResult = findResult(results, "yara_scan");

  const unavailable = assessment && Array.isArray(assessment.providers_unavailable)
    ? (assessment.providers_unavailable as unknown[]).map(String)
    : [];
  const failed = assessment && Array.isArray(assessment.providers_failed)
    ? (assessment.providers_failed as unknown[]).map(String)
    : [];

  const consultedRows = ["virustotal", "malwarebazaar", "hybrid_analysis", "otx"]
    .map((key) => {
      const result = findResult(results, MALWARE_SOURCE_NAMES[key]);
      if (!result || (result.status !== "success" && result.status !== "not_found")) {
        return null;
      }
      return {
        key,
        label: MALWARE_PROVIDER_LABELS[key],
        summary: summarizeMalwareProvider(key, result),
      };
    })
    .filter((row): row is { key: string; label: string; summary: string } => row !== null);

  const unavailableAll = [...new Set([...unavailable, ...failed])];

  return (
    <Section title="Malware Intelligence">
      {consultedRows.length > 0 ? (
        <ul className="space-y-1 text-sm text-slate-700 dark:text-slate-300">
          {consultedRows.map((row) => (
            <li key={row.key}>
              <span className="font-medium text-slate-900 dark:text-white">{row.label}:</span>{" "}
              {row.summary}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No malware intelligence provider returned data for this file.
        </p>
      )}

      <p className="mt-2 text-sm text-slate-700 dark:text-slate-300">
        <span className="font-medium text-slate-900 dark:text-white">YARA:</span>{" "}
        {!yaraResult || yaraResult.status === "skipped"
          ? "Not available in this deployment."
          : yara?.matched
          ? `${asNumber(yara.match_count) ?? "Some"} matching rule(s).`
          : "No matching YARA rules."}
      </p>

      {unavailableAll.length > 0 && (
        <div className="mt-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">
            Unavailable Providers
          </p>
          <ul className="mt-1 space-y-0.5 text-sm text-slate-500 dark:text-slate-400">
            {unavailableAll.map((name) => (
              <li key={name}>{MALWARE_PROVIDER_LABELS[name] ?? name} unavailable.</li>
            ))}
          </ul>
        </div>
      )}
    </Section>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-sm font-semibold text-slate-900 dark:text-white">
        {title}
      </h3>
      {children}
    </div>
  );
}

function FieldGrid({
  fields,
  mono = false,
}: {
  fields: [string, string][];
  mono?: boolean;
}) {
  if (fields.length === 0) {
    return (
      <p className="text-sm text-slate-500 dark:text-slate-400">
        No fields available.
      </p>
    );
  }

  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
      {fields.map(([label, value]) => (
        <div key={label} className="flex items-baseline justify-between gap-3 capitalize sm:block">
          <dt className="text-xs uppercase tracking-wide text-slate-400">{label}</dt>
          <dd
            className={`break-all normal-case text-slate-700 dark:text-slate-300 ${mono ? "font-mono text-xs" : ""}`}
          >
            {value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Callout({ children }: { children: React.ReactNode }) {
  return (
    <div className="mt-2 rounded-lg border border-orange-200 bg-orange-50 px-3 py-2 text-sm text-orange-700 dark:border-orange-900/50 dark:bg-orange-950/20 dark:text-orange-300">
      {children}
    </div>
  );
}
