import type { InvestigationResult } from "@/types/investigation";
import { formatBytes, formatDate } from "@/utils/formatters";
import { asBoolean, asNumber, asRecord, asString, findResult } from "@/utils/evidenceData";

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

  return (
    <div className="space-y-6">
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
    </div>
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
