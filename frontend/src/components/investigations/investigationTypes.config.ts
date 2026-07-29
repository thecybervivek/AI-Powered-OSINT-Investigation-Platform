import type { LucideIcon } from "lucide-react";
import {
  AtSign,
  Bug,
  FileSearch,
  FileText,
  Fingerprint,
  Globe,
  Image as ImageIcon,
  Layers,
  Network,
  Phone,
  Server,
  ShieldAlert,
  Users,
} from "lucide-react";

import type { InvestigationType } from "@/types/investigation";

/**
 * ==========================================================
 * TEMPORARY FRONTEND PRESENTATION METADATA - NOT THE REGISTRY
 * ==========================================================
 *
 * This file is Account 3's (this track's) frontend-only presentation
 * layer for the New Investigation UX: display label, description,
 * grouping, icon, and what kind of input control to render for each
 * investigation type.
 *
 * It intentionally carries NO backend business semantics - no
 * scoring, no evidence states, no provider/capability logic. Account
 * 2 owns the future Investigation Type / Capability Registry; once
 * that ships, this file should be deleted and replaced by data read
 * from that registry (label/description/category/icon/input-mode
 * would move server-side, and `available` would come from real
 * capability checks instead of being hand-maintained here).
 *
 * Every `type` value below must be a real `InvestigationType` the
 * backend enum already defines, and every type marked `available:
 * true` must have a real, wired-up backend endpoint - see
 * investigationService.ts. `metadata` is intentionally `available:
 * false`: InvestigationType.METADATA exists in the backend enum, but
 * no route currently creates that investigation type (no
 * `metadata.py` endpoint is registered in api/v1/router.py). Showing
 * it as disabled rather than omitting it keeps the category shape
 * from Part A's spec visible without faking support for it.
 */

export type InvestigationInputMode = "text" | "file" | "image" | "composite";

export type InvestigationCategory =
  | "Identity"
  | "Web & Infrastructure"
  | "File & Media"
  | "Threat Intelligence"
  | "Advanced";

export interface InvestigationTypeDefinition {
  type: InvestigationType;
  label: string;
  description: string;
  category: InvestigationCategory;
  icon: LucideIcon;
  inputMode: InvestigationInputMode;
  available: boolean;
  unavailableReason?: string;
  inputLabel?: string;
  placeholder?: string;
  helperText?: string;
}

export const INVESTIGATION_TYPE_DEFINITIONS: InvestigationTypeDefinition[] = [
  // ---- Identity ----
  {
    type: "username",
    label: "Username",
    description: "Discover public profiles and correlate username exposure.",
    category: "Identity",
    icon: AtSign,
    inputMode: "text",
    available: true,
    inputLabel: "Username",
    placeholder: "e.g. johndoe",
  },
  {
    type: "email",
    label: "Email",
    description: "Validate email infrastructure and investigate public exposure.",
    category: "Identity",
    icon: Fingerprint,
    inputMode: "text",
    available: true,
    inputLabel: "Email address",
    placeholder: "person@example.com",
  },
  {
    type: "phone",
    label: "Phone",
    description: "Validate and enrich phone-number intelligence.",
    category: "Identity",
    icon: Phone,
    inputMode: "text",
    available: true,
    inputLabel: "Phone number",
    placeholder: "+14155552671",
    helperText: "International format is recommended, e.g. +14155552671.",
  },
  {
    type: "social_media",
    label: "Social Media",
    description: "Discover public social profiles and correlation signals.",
    category: "Identity",
    icon: Users,
    inputMode: "text",
    available: true,
    inputLabel: "Username",
    placeholder: "e.g. johndoe",
  },

  // ---- Web & Infrastructure ----
  {
    type: "domain",
    label: "Domain",
    description: "Analyze DNS, registration, infrastructure and security signals.",
    category: "Web & Infrastructure",
    icon: Globe,
    inputMode: "text",
    available: true,
    inputLabel: "Domain",
    placeholder: "example.com",
    helperText: "Enter a bare domain such as example.com, not a full URL.",
  },
  {
    type: "ip_address",
    label: "IP Address",
    description: "Investigate network ownership, geolocation and threat signals.",
    category: "Web & Infrastructure",
    icon: Network,
    inputMode: "text",
    available: true,
    inputLabel: "IP address",
    placeholder: "8.8.8.8",
  },
  {
    type: "url",
    label: "URL",
    description: "Analyze URL infrastructure and security indicators.",
    category: "Web & Infrastructure",
    icon: FileSearch,
    inputMode: "text",
    available: true,
    inputLabel: "URL",
    placeholder: "https://example.com/path",
  },
  {
    type: "dns",
    label: "DNS Intelligence",
    description: "Inspect DNS records, mail security and certificate footprint.",
    category: "Web & Infrastructure",
    icon: Server,
    inputMode: "text",
    available: true,
    inputLabel: "Domain",
    placeholder: "example.com",
    helperText: "Enter a bare domain such as example.com.",
  },

  // ---- File & Media ----
  {
    type: "file",
    label: "File Analysis",
    description: "Analyze uploaded files, hashes, metadata and security indicators.",
    category: "File & Media",
    icon: FileText,
    inputMode: "file",
    available: true,
  },
  {
    type: "reverse_image",
    label: "Reverse Image",
    description: "Analyze image fingerprints, metadata and internal similarity.",
    category: "File & Media",
    icon: ImageIcon,
    inputMode: "image",
    available: true,
    helperText:
      "The image will be analyzed for fingerprints, metadata, and matches against previously investigated images.",
  },
  {
    type: "metadata",
    label: "Metadata",
    description: "Extract supported metadata from files/documents.",
    category: "File & Media",
    icon: FileSearch,
    inputMode: "file",
    available: false,
    unavailableReason: "Not yet available as a standalone investigation type.",
  },

  // ---- Threat Intelligence ----
  {
    type: "malware",
    label: "Malware Intelligence",
    description: "Investigate MD5, SHA-1 or SHA-256 indicators.",
    category: "Threat Intelligence",
    icon: Bug,
    inputMode: "text",
    available: true,
    inputLabel: "File hash",
    placeholder: "MD5, SHA-1, or SHA-256 hash",
    helperText: "Supported indicators: MD5, SHA-1, and SHA-256 file hashes.",
  },
  {
    type: "threat_intelligence",
    label: "Threat Intelligence",
    description: "Correlate supported IOC intelligence across configured providers.",
    category: "Threat Intelligence",
    icon: ShieldAlert,
    inputMode: "text",
    available: true,
    inputLabel: "Indicator",
    placeholder: "IP address or domain",
    helperText:
      "Host-based providers run against the resolved IP or domain.",
  },

  // ---- Advanced ----
  {
    type: "risk_assessment",
    label: "Composite Risk Assessment",
    description: "Combine existing investigations into a unified assessment.",
    category: "Advanced",
    icon: Layers,
    inputMode: "composite",
    available: true,
  },
];

// `breach` exists as an InvestigationType and has a working endpoint,
// but Part B's card spec (Part A's target list) does not list it as a
// selectable New Investigation entry point - it's currently reached
// indirectly (e.g. via Email Intelligence). Not included here on
// purpose, not an oversight.

export const CATEGORY_ORDER: InvestigationCategory[] = [
  "Identity",
  "Web & Infrastructure",
  "File & Media",
  "Threat Intelligence",
  "Advanced",
];

export function getInvestigationTypeDefinition(
  type: InvestigationType
): InvestigationTypeDefinition | undefined {
  return INVESTIGATION_TYPE_DEFINITIONS.find((def) => def.type === type);
}

export function searchInvestigationTypes(
  query: string
): InvestigationTypeDefinition[] {
  const trimmed = query.trim().toLowerCase();

  if (!trimmed) return INVESTIGATION_TYPE_DEFINITIONS;

  return INVESTIGATION_TYPE_DEFINITIONS.filter((def) =>
    [def.label, def.description, def.category]
      .join(" ")
      .toLowerCase()
      .includes(trimmed)
  );
}

