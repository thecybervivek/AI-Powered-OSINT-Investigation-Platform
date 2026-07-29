import { z } from "zod";

export const loginSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

export type LoginFormValues = z.infer<typeof loginSchema>;

export const registerSchema = z.object({
  full_name: z.string().min(2, "Full name must be at least 2 characters"),
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(50, "Username must be at most 50 characters"),
  email: z.string().email("Enter a valid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128, "Password must be at most 128 characters"),
});

export type RegisterFormValues = z.infer<typeof registerSchema>;

export const forgotPasswordSchema = z.object({
  email: z.string().email("Enter a valid email address"),
});

export type ForgotPasswordFormValues = z.infer<typeof forgotPasswordSchema>;

// ==========================================================
// Investigation target validation
// ==========================================================
//
// These mirror the backend's pydantic field_validators exactly (see
// backend/app/schemas/{domain,ip,url,dns_intelligence,phone,
// username,malware_intelligence,threat_intelligence}.py) so the UI
// rejects invalid input before it ever reaches the API - but the
// backend remains the source of truth and re-validates everything
// server-side regardless.

const DOMAIN_LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
const BARE_DOMAIN_PATTERN = new RegExp(`^(${DOMAIN_LABEL}\\.)+${DOMAIN_LABEL}$`);

function isIpAddress(value: string): boolean {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/;

  if (ipv4.test(value)) {
    return value.split(".").every((octet) => Number(octet) <= 255);
  }

  return ipv6.test(value) && value.includes(":");
}

export const usernameTargetSchema = z
  .string()
  .trim()
  .min(1, "Enter a username")
  .max(64, "Username must be 64 characters or fewer")
  .regex(
    /^[A-Za-z0-9_.-]+$/,
    "Username may only contain letters, numbers, dots, underscores, and hyphens"
  );

export const emailTargetSchema = z
  .string()
  .trim()
  .min(1, "Enter an email address")
  .email("Enter a valid email address");

// Domain investigation accepts a bare domain *or* an IP address (the
// service resolves either) - matches DomainInvestigationRequest.target.
export const domainOrIpTargetSchema = z
  .string()
  .trim()
  .min(1, "Enter a domain or IP address")
  .max(253, "Value is too long")
  .refine(
    (value) => isIpAddress(value) || BARE_DOMAIN_PATTERN.test(value.toLowerCase()),
    {
      message:
        "Enter a bare domain such as example.com (not a full URL), or an IP address",
    }
  );

// IP/Threat Intelligence targets are more permissive - any non-empty
// value without a path or space is accepted and resolved server-side.
export const hostOrIpTargetSchema = z
  .string()
  .trim()
  .min(1, "Enter an IP address or domain")
  .max(253, "Value is too long")
  .refine((value) => !value.includes("/") && !value.includes(" "), {
    message: "Enter a bare IP address or domain, without a path",
  });

// DNS Intelligence requires a strict bare domain (no IPs).
export const bareDomainTargetSchema = z
  .string()
  .trim()
  .min(1, "Enter a domain")
  .max(253, "Value is too long")
  .refine((value) => BARE_DOMAIN_PATTERN.test(value.toLowerCase()), {
    message: "Enter a domain such as google.com, not a full URL",
  });

export const urlTargetSchema = z
  .string()
  .trim()
  .min(1, "Enter a URL")
  .max(2048, "URL is too long")
  .refine(
    (value) => {
      try {
        const parsed = new URL(value);
        return (
          (parsed.protocol === "http:" || parsed.protocol === "https:") &&
          Boolean(parsed.host)
        );
      } catch {
        return false;
      }
    },
    { message: "Enter a full URL, e.g. https://example.com/path" }
  );

export const phoneTargetSchema = z
  .string()
  .trim()
  .min(3, "Enter a phone number")
  .max(32, "Phone number is too long")
  .regex(
    /^[\d+\-.\s()]{3,20}$/,
    "Phone number may only contain digits, spaces, '+', '-', '.', and parentheses"
  );

export type HashType = "MD5" | "SHA-1" | "SHA-256";

export function detectHashType(value: string): HashType | null {
  const trimmed = value.trim();

  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return "MD5";
  if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return "SHA-1";
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return "SHA-256";

  return null;
}

export const malwareHashTargetSchema = z
  .string()
  .trim()
  .refine((value) => detectHashType(value) !== null, {
    message: "Enter a valid MD5 (32), SHA-1 (40), or SHA-256 (64) hex hash",
  });

export const assessmentLabelSchema = z
  .string()
  .trim()
  .max(200, "Name must be 200 characters or fewer");

