import { ShieldAlert, ShieldCheck, ShieldQuestion, Ban } from "lucide-react";
import clsx from "clsx";

import type { InvestigationResult } from "@/types/investigation";
import { formatDate } from "@/utils/formatters";
import { asBoolean, asNumber, asRecord, asString, findResult } from "@/utils/evidenceData";

interface DomainIntelligenceProps {
  results: InvestigationResult[];
}

const RECORD_TYPE_ORDER = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"];

/**
 * Built strictly from what the rearchitected domain_service.py
 * actually persists (verified by reading that file directly - it was
 * rewritten in this same session, not assumed):
 *   dns_lookup               -> records: {A, AAAA, CNAME, MX, NS, TXT, SOA, CAA}
 *   whois                    -> registrar, dates, domain_statuses, dnssec,
 *                                domain_age_days, name_servers
 *   ssl_certificate          -> subject, issuer, validity, SANs, fingerprint
 *   technology_detection     -> technologies_detected, relevant_headers
 *   certificate_transparency -> discovered subdomains (not "resolved")
 *   subdomain_resolution_sample -> a bounded resolved/unresolved sample
 *   ip_intelligence_summary  -> ASN/geolocation/reverse-DNS aggregated per
 *                                resolved public IP
 *   dns_resolution_notes     -> non-public resolved addresses, if any
 *   threat_assessment        -> the evidence-backed assessment state that
 *                                replaces a bare risk score as the primary
 *                                conclusion for this module
 */
export function DomainIntelligence({ results }: DomainIntelligenceProps) {
  const dnsLookup = asRecord(findResult(results, "dns_lookup")?.data);
  const whois = asRecord(findResult(results, "whois")?.data);
  const ssl = asRecord(findResult(results, "ssl_certificate")?.data);
  const technology = asRecord(findResult(results, "technology_detection")?.data);
  const ctResult = findResult(results, "certificate_transparency");
  const subdomainSample = asRecord(findResult(results, "subdomain_resolution_sample")?.data);
  const ipSummary = asRecord(findResult(results, "ip_intelligence_summary")?.data);
  const dnsNotes = asRecord(findResult(results, "dns_resolution_notes")?.data);
  const assessment = asRecord(findResult(results, "threat_assessment")?.data);

  return (
    <div className="space-y-6">
      {assessment && <AssessmentBanner assessment={assessment} />}

      {dnsLookup && <DnsRecordsSection dnsLookup={dnsLookup} />}

      {whois && <WhoisSection whois={whois} />}

      {ssl && <TlsSection ssl={ssl} />}

      {technology && <TechnologySection technology={technology} />}

      {(ctResult || subdomainSample) && (
        <SubdomainSection ctResult={ctResult} sample={subdomainSample} />
      )}

      {(ipSummary || dnsNotes) && (
        <IpIntelligenceSection ipSummary={ipSummary} dnsNotes={dnsNotes} />
      )}

      {assessment && <ThreatIntelligenceSection results={results} assessment={assessment} />}
    </div>
  );
}

// ==========================================================
// Assessment
// ==========================================================

const ASSESSMENT_ICONS: Record<string, typeof ShieldCheck> = {
  malicious: Ban,
  suspicious: ShieldAlert,
  no_malicious_evidence_detected: ShieldCheck,
  inconclusive: ShieldQuestion,
  threat_assessment_incomplete: ShieldQuestion,
  // Reverse Image's own distinct states (production polish).
  image_matches_found: ShieldAlert,
  no_public_matches_found: ShieldCheck,
  metadata_only: ShieldQuestion,
  investigation_incomplete: ShieldQuestion,
};

const ASSESSMENT_TONES: Record<string, string> = {
  malicious:
    "border-red-200 bg-red-50 text-red-700 dark:border-red-900/50 dark:bg-red-950/20 dark:text-red-300",
  suspicious:
    "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/50 dark:bg-orange-950/20 dark:text-orange-300",
  no_malicious_evidence_detected:
    "border-green-200 bg-green-50 text-green-700 dark:border-green-900/50 dark:bg-green-950/20 dark:text-green-300",
  inconclusive:
    "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300",
  threat_assessment_incomplete:
    "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300",
  // Reverse Image's own distinct states (production polish).
  image_matches_found:
    "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900/50 dark:bg-orange-950/20 dark:text-orange-300",
  no_public_matches_found:
    "border-green-200 bg-green-50 text-green-700 dark:border-green-900/50 dark:bg-green-950/20 dark:text-green-300",
  metadata_only:
    "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300",
  investigation_incomplete:
    "border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/50 dark:text-slate-300",
};

export function AssessmentBanner({ assessment }: { assessment: Record<string, unknown> }) {
  const state = asString(assessment.state) ?? "threat_assessment_incomplete";
  const label = asString(assessment.label) ?? "Threat assessment incomplete";
  const reasoning = Array.isArray(assessment.reasoning)
    ? (assessment.reasoning as unknown[]).map(String)
    : [];
  const consulted = Array.isArray(assessment.providers_consulted)
    ? (assessment.providers_consulted as unknown[]).map(String)
    : [];
  const unavailable = Array.isArray(assessment.providers_unavailable)
    ? (assessment.providers_unavailable as unknown[]).map(String)
    : [];

  const Icon = ASSESSMENT_ICONS[state] ?? ShieldQuestion;

  return (
    <div className={clsx("rounded-lg border p-4", ASSESSMENT_TONES[state])}>
      <div className="flex items-center gap-2">
        <Icon className="h-5 w-5 shrink-0" />
        <span className="font-semibold">{label}</span>
      </div>

      {state === "no_malicious_evidence_detected" && (
        <p className="mt-1 text-xs opacity-90">
          No configured threat/reputation source flagged this domain or its
          infrastructure. This reflects what was actually checked below -
          it is not a guarantee of safety.
        </p>
      )}

      {reasoning.length > 0 && (
        <ul className="mt-2 list-inside list-disc space-y-0.5 text-sm">
          {reasoning.map((line, index) => (
            <li key={index}>{line}</li>
          ))}
        </ul>
      )}

      <p className="mt-2 text-xs opacity-75">
        {consulted.length > 0
          ? `Consulted: ${consulted.join(", ")}.`
          : "No provider was consulted."}
        {unavailable.length > 0 && ` Unavailable: ${unavailable.join(", ")}.`}
      </p>
    </div>
  );
}

// ==========================================================
// DNS Records
// ==========================================================

export function DnsRecordsSection({ dnsLookup }: { dnsLookup: Record<string, unknown> }) {
  const records = asRecord(dnsLookup.records) ?? {};
  const domainExists = asBoolean(dnsLookup.domain_exists);

  const nonEmptyTypes = RECORD_TYPE_ORDER.filter((type) => {
    const values = records[type];
    return Array.isArray(values) && values.length > 0;
  });

  return (
    <Section title="DNS Records">
      {domainExists === false ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          This domain does not resolve (NXDOMAIN).
        </p>
      ) : nonEmptyTypes.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No DNS records were found for the queried types.
        </p>
      ) : (
        <div className="space-y-3">
          {nonEmptyTypes.map((type) => (
            <div key={type}>
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                {type}
              </p>
              <ul className="mt-1 space-y-0.5 font-mono text-xs text-slate-700 dark:text-slate-300">
                {(records[type] as unknown[]).map((value, index) => (
                  <li key={index} className="break-all">
                    {String(value)}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}

// ==========================================================
// WHOIS
// ==========================================================

export function WhoisSection({ whois }: { whois: Record<string, unknown> }) {
  if (asBoolean(whois.registered) === false) {
    return (
      <Section title="Registration">
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No registration record found - this domain appears unregistered.
        </p>
      </Section>
    );
  }

  const statuses = Array.isArray(whois.domain_statuses)
    ? (whois.domain_statuses as unknown[]).map(String)
    : [];
  const nameServers = Array.isArray(whois.name_servers)
    ? (whois.name_servers as unknown[]).map(String)
    : [];
  const ageDays = asNumber(whois.domain_age_days);
  const created = asString(whois.creation_date);
  const expires = asString(whois.expiration_date);

  return (
    <Section title="Registration">
      <FieldGrid
        fields={[
          ["Registrar", asString(whois.registrar) ?? "Not disclosed"],
          ["Registered", created ? (extractYear(created) ?? created) : "—"],
          ["Expires", expires ? (extractYear(expires) ?? expires) : "—"],
          ["Domain age", ageDays !== null ? `${ageDays.toLocaleString()} days` : "—"],
          ["DNSSEC", asString(whois.dnssec) ?? "Not reported"],
        ]}
      />

      {statuses.length > 0 && (
        <div className="mt-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">Domain status</p>
          <p className="mt-1 text-sm text-slate-700 dark:text-slate-300">
            {statuses.join(", ")}
          </p>
        </div>
      )}

      {nameServers.length > 0 && (
        <div className="mt-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">Nameservers</p>
          <p className="mt-1 font-mono text-xs text-slate-700 dark:text-slate-300">
            {nameServers.join(", ")}
          </p>
        </div>
      )}

      <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
        Missing registrant details are typically privacy redaction, not a
        red flag - most registrars redact this by default.
      </p>
    </Section>
  );
}

// ==========================================================
// TLS
// ==========================================================

export function TlsSection({ ssl }: { ssl: Record<string, unknown> }) {
  if (asBoolean(ssl.certificate_valid) === false) {
    return (
      <Section title="TLS Certificate">
        <p className="text-sm text-red-600 dark:text-red-400">
          Certificate verification failed
          {asString(ssl.verification_error) ? `: ${ssl.verification_error}` : "."}
        </p>
      </Section>
    );
  }

  const subject = asRecord(ssl.subject);
  const issuer = asRecord(ssl.issuer);
  const sans = Array.isArray(ssl.subject_alt_names)
    ? (ssl.subject_alt_names as unknown[]).map(String)
    : [];
  const issuerName = asString(issuer?.organizationName ?? issuer?.commonName);
  const notAfter = asString(ssl.not_after);

  return (
    <Section title="TLS Certificate">
      <p className="text-sm text-slate-700 dark:text-slate-300">
        {asBoolean(ssl.is_expired)
          ? `Expired ${notAfter ? formatMonthYear(notAfter) : ""}`
          : notAfter
          ? `Valid until ${formatMonthYear(notAfter)}`
          : "Validity period unknown"}
        {issuerName && `, issued by ${issuerName}`}.
      </p>

      <FieldGrid
        fields={[
          ["Subject (CN)", asString(subject?.commonName) ?? "—"],
          ["Issuer", issuerName ?? "—"],
          ["Not before", asString(ssl.not_before) ? formatDate(asString(ssl.not_before)) : "—"],
          ["Not after", notAfter ? formatDate(notAfter) : "—"],
          ["Expired", asBoolean(ssl.is_expired) ? "Yes" : "No"],
        ]}
      />

      {asString(ssl.fingerprint_sha256) && (
        <p className="mt-2 break-all font-mono text-xs text-slate-500 dark:text-slate-400">
          SHA-256: {ssl.fingerprint_sha256 as string}
        </p>
      )}

      {sans.length > 0 && (
        <div className="mt-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">
            Subject Alternative Names
          </p>
          <p className="mt-1 break-all font-mono text-xs text-slate-700 dark:text-slate-300">
            {sans.join(", ")}
          </p>
        </div>
      )}
    </Section>
  );
}

// ==========================================================
// Technology
// ==========================================================

export function TechnologySection({ technology }: { technology: Record<string, unknown> }) {
  const detected = Array.isArray(technology.technologies_detected)
    ? (technology.technologies_detected as unknown[]).map(String)
    : [];
  const headers = asRecord(technology.relevant_headers) ?? {};

  return (
    <Section title="Technology">
      {detected.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No known technology signatures matched. This reflects the
          heuristics checked, not a confirmed absence of any technology.
        </p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {detected.map((tech) => (
            <span
              key={tech}
              className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300"
            >
              {tech}
            </span>
          ))}
        </div>
      )}

      {Object.keys(headers).length > 0 && (
        <div className="mt-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">
            Supporting evidence (headers)
          </p>
          <dl className="mt-1 space-y-0.5 text-xs text-slate-600 dark:text-slate-400">
            {Object.entries(headers).map(([key, value]) => (
              <div key={key} className="break-all">
                <span className="font-mono">{key}</span>: {String(value)}
              </div>
            ))}
          </dl>
        </div>
      )}
    </Section>
  );
}

// ==========================================================
// Subdomains
// ==========================================================

function SubdomainSection({
  ctResult,
  sample,
}: {
  ctResult: InvestigationResult | undefined;
  sample: Record<string, unknown> | null;
}) {
  const ct = asRecord(ctResult?.data);
  const subdomains = ct && Array.isArray(ct.subdomains) ? (ct.subdomains as unknown[]).map(String) : [];
  const resolved = sample && Array.isArray(sample.resolved) ? (sample.resolved as unknown[]).map(String) : [];
  const unresolved = sample && Array.isArray(sample.unresolved) ? (sample.unresolved as unknown[]).map(String) : [];

  const ctUnavailable = ctResult?.status === "failed";

  return (
    <Section title="Subdomains">
      {ctUnavailable ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          {ctResult?.error_message || "Certificate Transparency temporarily unavailable."}
        </p>
      ) : subdomains.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No subdomains discovered via Certificate Transparency logs. This is
          a passive source (crt.sh) - it does not imply exhaustive coverage.
        </p>
      ) : (
        <>
          <p className="text-sm text-slate-600 dark:text-slate-400">
            {subdomains.length} discovered via Certificate Transparency logs
            (crt.sh) - names that appeared on a publicly issued certificate,
            not necessarily still active.
          </p>

          {sample && (
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              {asString(sample.note)}
            </p>
          )}

          <div className="mt-2 max-h-48 overflow-y-auto rounded-lg border border-slate-100 dark:border-slate-800">
            <ul className="divide-y divide-slate-100 text-xs dark:divide-slate-800">
              {subdomains.slice(0, 100).map((name) => {
                const status = resolved.includes(name)
                  ? "resolved"
                  : unresolved.includes(name)
                  ? "unresolved"
                  : "not sampled";

                return (
                  <li
                    key={name}
                    className="flex items-center justify-between gap-2 px-2 py-1 font-mono"
                  >
                    <span className="truncate">{name}</span>
                    <span
                      className={clsx(
                        "shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-sans uppercase",
                        status === "resolved" &&
                          "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300",
                        status === "unresolved" &&
                          "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
                        status === "not sampled" &&
                          "bg-slate-50 text-slate-400 dark:bg-slate-900 dark:text-slate-500"
                      )}
                    >
                      {status}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        </>
      )}
    </Section>
  );
}

// ==========================================================
// IP Intelligence
// ==========================================================

function IpIntelligenceSection({
  ipSummary,
  dnsNotes,
}: {
  ipSummary: Record<string, unknown> | null;
  dnsNotes: Record<string, unknown> | null;
}) {
  const ips = ipSummary && Array.isArray(ipSummary.ips) ? (ipSummary.ips as Record<string, unknown>[]) : [];

  const rows = ips.map((entry) => {
    const ip = asString(entry.ip_address) ?? "Unknown IP";
    const asn = asRecord(entry.asn);
    const geo = asRecord(entry.geolocation);
    const rdns = asRecord(entry.reverse_dns);

    const asnData = asn?.status === "success" ? asRecord(asn.data) : null;
    const geoData = geo?.status === "success" ? asRecord(geo.data) : null;
    const rdnsData = rdns?.status === "success" ? asRecord(rdns.data) : null;
    const rdnsHostnames =
      rdnsData && Array.isArray(rdnsData.hostnames) ? (rdnsData.hostnames as unknown[]).map(String) : [];

    const isIpv6NotSupported = asn?.status === "skipped" && ip.includes(":");

    return {
      ip,
      asn: asnData
        ? `${asString(asnData.asn) ?? "?"} (${asString(asnData.asn_name) ?? "unknown org"})`
        : isIpv6NotSupported
        ? "Not supported"
        : asn?.status === "skipped"
        ? "Not applicable"
        : "Not found",
      country: geoData ? asString(geoData.country) ?? "Unknown" : "—",
      reverseDns: rdnsHostnames.length > 0 ? rdnsHostnames.join(", ") : "None",
      isIpv6NotSupported,
    };
  });

  const anyIpv6Unsupported = rows.some((row) => row.isIpv6NotSupported);

  return (
    <Section title="IP Intelligence">
      {rows.length === 0 ? (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          No public IP address was resolved for this domain, so ASN,
          geolocation, and reverse DNS were not applicable.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-100 dark:border-slate-800">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-100 text-xs uppercase tracking-wide text-slate-400 dark:border-slate-800">
                <th className="px-3 py-2 font-medium">IP</th>
                <th className="px-3 py-2 font-medium">ASN</th>
                <th className="px-3 py-2 font-medium">Country</th>
                <th className="px-3 py-2 font-medium">Reverse DNS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {rows.map((row) => (
                <tr key={row.ip}>
                  <td className="px-3 py-2 font-mono text-xs text-slate-900 dark:text-white">
                    {row.ip}
                  </td>
                  <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{row.asn}</td>
                  <td className="px-3 py-2 text-slate-700 dark:text-slate-300">{row.country}</td>
                  <td className="px-3 py-2 text-slate-700 dark:text-slate-300">
                    {row.reverseDns}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {anyIpv6Unsupported && (
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
          IPv6 ASN lookup is not supported by the current provider.
        </p>
      )}

      {dnsNotes && Array.isArray(dnsNotes.non_public_ips_excluded) && (
        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
          Also resolved to{" "}
          {(dnsNotes.non_public_ips_excluded as unknown[]).map(String).join(", ")}
          , which {(dnsNotes.non_public_ips_excluded as unknown[]).length === 1 ? "is" : "are"}{" "}
          not public - excluded from IP-dependent intelligence.
        </p>
      )}
    </Section>
  );
}

// ==========================================================
// Threat Intelligence
// ==========================================================

const PROVIDER_LABELS: Record<string, string> = {
  shodan: "Shodan",
  censys: "Censys",
  greynoise: "GreyNoise",
  otx: "OTX",
  securitytrails: "SecurityTrails",
};

function findByPrefix(
  results: InvestigationResult[],
  prefix: string
): InvestigationResult | undefined {
  return results.find(
    (result) => result.source === prefix || result.source.startsWith(`${prefix}:`)
  );
}

function summarizeProvider(key: string, result: InvestigationResult): string | null {
  const data = asRecord(result.data);

  if (!data) return "Ran, no additional detail returned.";

  if (key === "greynoise") {
    const classification = asString(data.classification) ?? "unknown";
    const isRiot = asBoolean(data.is_common_business_service);
    const isNoise = asBoolean(data.is_internet_noise);

    if (isRiot) return "Identified as a known, common business service.";
    if (isNoise) return `Internet-wide scanning observed, classified as ${classification}.`;
    return "No internet-wide scanning activity observed.";
  }

  if (key === "otx") {
    const pulseCount = asNumber(data.pulse_count) ?? 0;
    return pulseCount > 0
      ? `Referenced in ${pulseCount} community threat pulse${pulseCount === 1 ? "" : "s"}.`
      : "Not referenced in any community threat pulses.";
  }

  if (key === "shodan") {
    const vulnCount = Array.isArray(data.vulnerabilities) ? data.vulnerabilities.length : 0;
    const openPorts = Array.isArray(data.open_ports) ? data.open_ports.length : 0;
    return vulnCount > 0
      ? `${openPorts} open port${openPorts === 1 ? "" : "s"}, ${vulnCount} known CVE${vulnCount === 1 ? "" : "s"} listed.`
      : `${openPorts} open port${openPorts === 1 ? "" : "s"}, no known CVEs listed.`;
  }

  if (key === "censys") {
    const services = Array.isArray(data.services) ? data.services.length : null;
    return services !== null
      ? `${services} exposed service${services === 1 ? "" : "s"} observed.`
      : "Ran, no additional detail returned.";
  }

  return "Ran, no additional detail returned.";
}

function ThreatIntelligenceSection({
  results,
  assessment,
}: {
  results: InvestigationResult[];
  assessment: Record<string, unknown>;
}) {
  const unavailable = Array.isArray(assessment.providers_unavailable)
    ? (assessment.providers_unavailable as unknown[]).map(String)
    : [];
  const failed = Array.isArray(assessment.providers_failed)
    ? (assessment.providers_failed as unknown[]).map(String)
    : [];

  const consultedRows = ["shodan", "censys", "greynoise", "otx"]
    .map((key) => {
      const result = findByPrefix(results, key);
      if (!result || result.status !== "success") return null;
      return { key, label: PROVIDER_LABELS[key] ?? key, summary: summarizeProvider(key, result) };
    })
    .filter((row): row is { key: string; label: string; summary: string | null } => row !== null);

  const unavailableAll = [...new Set([...unavailable, ...failed])];

  return (
    <Section title="Threat Intelligence">
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
          No threat intelligence provider returned data for this investigation.
        </p>
      )}

      {unavailableAll.length > 0 && (
        <div className="mt-3">
          <p className="text-xs uppercase tracking-wide text-slate-400">
            Unavailable Providers
          </p>
          <ul className="mt-1 space-y-0.5 text-sm text-slate-500 dark:text-slate-400">
            {unavailableAll.map((name) => (
              <li key={name}>{PROVIDER_LABELS[name] ?? name}</li>
            ))}
          </ul>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Unavailable providers were not counted toward the assessment
            above - they simply did not run.
          </p>
        </div>
      )}
    </Section>
  );
}

// ==========================================================
// Shared bits
// ==========================================================

export function formatMonthYear(isoString: string): string {
  const parsed = new Date(isoString);

  if (Number.isNaN(parsed.getTime())) {
    return isoString;
  }

  return parsed.toLocaleDateString(undefined, { month: "short", year: "numeric" });
}

export function extractYear(rawDate: string): string | null {
  const trimmed = rawDate.trim();

  if (/^\d{4}/.test(trimmed)) {
    return trimmed.slice(0, 4);
  }

  const match = trimmed.match(/\b(\d{4})\b/);
  return match ? match[1] : null;
}

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      {children}
    </div>
  );
}

export function FieldGrid({ fields }: { fields: [string, string][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
      {fields.map(([label, value]) => (
        <div key={label} className="flex items-baseline justify-between gap-3 sm:block">
          <dt className="text-xs uppercase tracking-wide text-slate-400">{label}</dt>
          <dd className="break-all text-slate-700 dark:text-slate-300">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

