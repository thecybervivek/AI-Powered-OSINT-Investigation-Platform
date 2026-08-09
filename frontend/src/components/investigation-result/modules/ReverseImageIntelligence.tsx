import { Link } from "react-router-dom";
import { MapPin } from "lucide-react";

import type { InvestigationResult } from "@/types/investigation";
import { formatBytes } from "@/utils/formatters";
import {
  asBoolean,
  asNumber,
  asRecord,
  asString,
  findResult,
} from "@/utils/evidenceData";
import { AssessmentBanner } from "./DomainIntelligence";

interface ReverseImageIntelligenceProps {
  results: InvestigationResult[];
}

/**
 * Built strictly from what reverse_image_service.py actually writes
 * into InvestigationResult.data today (verified by reading that file
 * directly in this session, not assumed):
 *   file_validation    -> declared_extension, detected_mime_type,
 *                          file_size_bytes, has_double_extension,
 *                          suspicious_extension, errors
 *   hash_analysis      -> md5, sha1, sha256, sha512
 *   perceptual_hashing -> phash, ahash, dhash, width, height
 *   metadata_extraction-> format, mode, width, height, exif, gps,
 *                          error, supported
 *   duplicate_detection-> exact_duplicate_found,
 *                          exact_duplicate_investigation_id,
 *                          near_duplicate_found,
 *                          closest_match_investigation_id,
 *                          closest_match_hamming_distance,
 *                          similarity_score
 * No public/internet-wide reverse-image-search data exists anywhere
 * in the backend today - this renderer does not claim that
 * capability.
 */
export function ReverseImageIntelligence({ results }: ReverseImageIntelligenceProps) {
  const validation = asRecord(findResult(results, "file_validation")?.data);
  const hashes = asRecord(findResult(results, "hash_analysis")?.data);
  const perceptual = asRecord(findResult(results, "perceptual_hashing")?.data);
  const metadata = asRecord(findResult(results, "metadata_extraction")?.data);
  const duplicates = asRecord(findResult(results, "duplicate_detection")?.data);
  const assessment = asRecord(findResult(results, "threat_assessment")?.data);

  const exif = metadata ? asRecord(metadata.exif) : null;
  const gps = metadata ? asRecord(metadata.gps) : null;

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
            <Callout tone="warning">
              This file's extension was flagged as suspicious during
              validation.
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

      {perceptual && Object.keys(perceptual).length > 0 && (
        <Section title="Perceptual Fingerprints">
          <FieldGrid
            mono
            fields={[
              ["pHash", asString(perceptual.phash) ?? "—"],
              ["aHash", asString(perceptual.ahash) ?? "—"],
              ["dHash", asString(perceptual.dhash) ?? "—"],
            ]}
          />
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Perceptual hashes measure visual similarity, not
            cryptographic identity - two different images can share a
            similar perceptual hash.
          </p>
        </Section>
      )}

      {metadata && (
        <Section title="Metadata / EXIF">
          {metadata.error ? (
            <Callout tone="warning">
              Metadata extraction failed: {asString(metadata.error)}
            </Callout>
          ) : metadata.supported === false ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Metadata extraction is not supported for this file type.
            </p>
          ) : exif && Object.keys(exif).length > 0 ? (
            <FieldGrid
              fields={Object.entries(exif).map(([key, value]) => [
                key,
                String(value),
              ])}
            />
          ) : (
            <p className="text-sm text-slate-500 dark:text-slate-400">
              No EXIF metadata found in this image. This does not
              confirm the image is unedited or unmodified - many tools
              and platforms strip metadata on save or export.
            </p>
          )}
        </Section>
      )}

      {gps && Object.keys(gps).length > 0 && (
        <Section title="Location Intelligence" icon={<MapPin className="h-4 w-4" />}>
          <FieldGrid
            fields={Object.entries(gps).map(([key, value]) => [
              key,
              String(value),
            ])}
          />
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Coordinates as embedded in the file's own EXIF GPS data at
            capture or last edit - not derived or inferred from the
            image's visual content.
          </p>
        </Section>
      )}

      {duplicates && (
        <Section title="Duplicate / Similarity Detection">
          <div className="space-y-2 text-sm">
            <p>
              <span className="font-medium text-slate-900 dark:text-white">
                Exact match:
              </span>{" "}
              {asBoolean(duplicates.exact_duplicate_found) ? (
                <>
                  Yes - identical to a previously investigated image
                  {asString(duplicates.exact_duplicate_investigation_id) && (
                    <>
                      {" ("}
                      <Link
                        to={`/investigations/${duplicates.exact_duplicate_investigation_id}`}
                        className="text-brand-600 hover:underline"
                      >
                        view investigation
                      </Link>
                      {")"}
                    </>
                  )}
                </>
              ) : (
                "None found"
              )}
            </p>

            <p>
              <span className="font-medium text-slate-900 dark:text-white">
                Closest visual match:
              </span>{" "}
              {asNumber(duplicates.closest_match_hamming_distance) !== null ? (
                <>
                  {asNumber(duplicates.similarity_score)}% similarity
                  {asBoolean(duplicates.near_duplicate_found)
                    ? " (near-duplicate threshold met)"
                    : " (below near-duplicate threshold)"}
                  {asString(duplicates.closest_match_investigation_id) && (
                    <>
                      {" - "}
                      <Link
                        to={`/investigations/${duplicates.closest_match_investigation_id}`}
                        className="text-brand-600 hover:underline"
                      >
                        view investigation
                      </Link>
                    </>
                  )}
                </>
              ) : (
                "No previously investigated image with a comparable perceptual hash"
              )}
            </p>

            <p className="text-xs text-slate-500 dark:text-slate-400">
              Similarity is measured only against images this account
              has previously investigated - not against the public
              internet. Visual similarity indicates the images may be
              related; it does not, by itself, identify who is in them
              or confirm they are the same file.
            </p>
          </div>
        </Section>
      )}

      {assessment && <ReverseSearchProvidersSection assessment={assessment} />}
    </div>
  );
}

const REVERSE_SEARCH_PROVIDER_LABELS: Record<string, string> = {
  google_lens: "Google Lens",
  bing_visual_search: "Bing Visual Search",
  tineye: "TinEye",
  yandex: "Yandex",
  saucenao: "SauceNAO",
  iqdb: "IQDB",
};

function ReverseSearchProvidersSection({
  assessment,
}: {
  assessment: Record<string, unknown>;
}) {
  const unavailable = Array.isArray(assessment.providers_unavailable)
    ? (assessment.providers_unavailable as unknown[]).map(String)
    : [];

  if (unavailable.length === 0) return null;

  return (
    <Section title="Public Reverse Image Search">
      <p className="mb-2 text-sm text-slate-500 dark:text-slate-400">
        No public reverse-image-search provider is configured in this
        deployment. Matches above reflect only this account's own
        previously investigated images, not a public web search.
      </p>
      <p className="text-xs uppercase tracking-wide text-slate-400">
        Unavailable Providers
      </p>
      <ul className="mt-1 space-y-0.5 text-sm text-slate-500 dark:text-slate-400">
        {unavailable.map((name) => (
          <li key={name}>{REVERSE_SEARCH_PROVIDER_LABELS[name] ?? name}</li>
        ))}
      </ul>
    </Section>
  );
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h3 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-slate-900 dark:text-white">
        {icon}
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
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
      {fields.map(([label, value]) => (
        <div key={label} className="flex items-baseline justify-between gap-3 sm:block">
          <dt className="text-xs uppercase tracking-wide text-slate-400">{label}</dt>
          <dd
            className={`break-all text-slate-700 dark:text-slate-300 ${mono ? "font-mono text-xs" : ""}`}
          >
            {value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Callout({
  tone,
  children,
}: {
  tone: "warning";
  children: React.ReactNode;
}) {
  const toneClasses =
    tone === "warning"
      ? "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/50 dark:bg-orange-950/20 dark:text-orange-300"
      : "";

  return (
    <div className={`mt-2 rounded-lg border px-3 py-2 text-sm ${toneClasses}`}>
      {children}
    </div>
  );
}
