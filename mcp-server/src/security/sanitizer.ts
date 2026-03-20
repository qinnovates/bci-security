/**
 * Report sanitization — implements SAFETY.md Section 4.
 * Applied to ALL output from report-generating tools.
 *
 * All regex patterns stored as {source, flags} to avoid lastIndex statefulness.
 * Fresh RegExp instances created per call.
 */

import { redactCredentials } from "./credential-redactor.js";
import { INJECTION_TRIGGERS } from "./injection.js";

export interface SanitizeOptions {
  includeOrg?: boolean;
  includeRelativePaths?: boolean;
}

interface PatternDef {
  source: string;
  flags: string;
}

// Absolute path patterns that must always be stripped
const ABSOLUTE_PATH_PATTERNS: PatternDef[] = [
  { source: "\\/Users\\/[^\\s'\",)}\\]]+", flags: "g" },
  { source: "\\/home\\/[^\\s'\",)}\\]]+", flags: "g" },
  { source: "C:\\\\Users\\\\[^\\s'\",)}\\]]+", flags: "gi" },
  { source: "\\/var\\/[^\\s'\",)}\\]]+", flags: "g" },
  { source: "\\/srv\\/[^\\s'\",)}\\]]+", flags: "g" },
  { source: "\\/opt\\/[^\\s'\",)}\\]]+", flags: "g" },
  { source: "\\/etc\\/[^\\s'\",)}\\]]+", flags: "g" },
];

// IPv4 addresses
const IPV4_PATTERN: PatternDef = {
  source: "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
  flags: "g",
};

// Internal URLs / hostnames with ports
const INTERNAL_URL_PATTERN: PatternDef = {
  source: "https?:\\/\\/(?:localhost|127\\.0\\.0\\.1|10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)(?::\\d+)?[^\\s]*",
  flags: "g",
};

// Environment details
const ENV_PATTERNS: PatternDef[] = [
  { source: "(?:OS|Platform|System|Arch):\\s*[^\\n]+", flags: "gi" },
  { source: "(?:Node|Python|npm|yarn)\\s+v?[\\d.]+", flags: "gi" },
];

function applyPattern(text: string, pattern: PatternDef, replacement: string): string {
  return text.replace(new RegExp(pattern.source, pattern.flags), replacement);
}

/**
 * Sanitize report text according to the 7 rules in SAFETY.md Section 4.
 */
export function sanitizeReport(text: string, _options: SanitizeOptions = {}): string {
  let result = text;

  // Rule 1: Absolute paths -> stripped (never allow absolute paths, even with --include-paths)
  for (const pattern of ABSOLUTE_PATH_PATTERNS) {
    result = applyPattern(result, pattern, "[path]");
  }

  // Rule 2: Credentials -> [REDACTED:TYPE] (NO OPT-OUT)
  result = redactCredentials(result);

  // Rule 3: Hostnames, IPs, internal URLs
  result = applyPattern(result, IPV4_PATTERN, "[device-ip]");
  result = applyPattern(result, INTERNAL_URL_PATTERN, "[internal-url]");

  // Rule 7: Environment details -> stripped
  for (const pattern of ENV_PATTERNS) {
    result = applyPattern(result, pattern, "[env]");
  }

  // Rule 8: Output injection filtering (CWE-116, OWASP MCP06)
  // Prevent user-supplied content in reports from containing LLM instruction patterns
  // that could influence the host model reading this output
  result = filterOutputInjection(result);

  // Self-verification pass (SAFETY.md Section 4 mandatory)
  result = selfVerify(result);

  return result;
}

/**
 * Filter LLM instruction patterns from output to prevent indirect prompt injection
 * via tool output poisoning (OWASP MCP06:2025, CWE-116).
 *
 * When user-supplied code/text is reflected in report output, it could contain
 * instructions targeting the host LLM. Replace trigger phrases with [filtered].
 */
function filterOutputInjection(text: string): string {
  let result = text;
  const normalized = text.normalize("NFKC").toLowerCase();

  for (const trigger of INJECTION_TRIGGERS) {
    let searchFrom = 0;
    let pos: number;
    while ((pos = normalized.indexOf(trigger, searchFrom)) !== -1) {
      // Replace the trigger phrase in the original text, preserving surrounding context
      result =
        result.slice(0, pos) +
        "[filtered]" +
        result.slice(pos + trigger.length);
      searchFrom = pos + "[filtered]".length;
    }
  }

  return result;
}

/**
 * Self-verification pass: scan output one more time for anything that slipped through.
 */
function selfVerify(text: string): string {
  let result = text;

  // Re-check absolute paths
  for (const pattern of ABSOLUTE_PATH_PATTERNS) {
    result = applyPattern(result, pattern, "[path]");
  }

  // Re-check credentials
  result = redactCredentials(result);

  return result;
}
