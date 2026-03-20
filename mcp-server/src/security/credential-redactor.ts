/**
 * Credential detection and redaction — implements SAFETY.md Section 3.
 * No opt-out. No override. No exception.
 */

interface CredentialPattern {
  type: string;
  source: string;
  flags: string;
}

// Patterns stored as source strings — fresh RegExp created per call to avoid lastIndex drift
const CREDENTIAL_PATTERNS: readonly CredentialPattern[] = [
  { type: "AWS_ACCESS_KEY", source: "(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}", flags: "g" },
  { type: "AWS_SECRET_KEY", source: "(?:aws_secret)[_\\s]*=?\\s*[A-Za-z0-9/+=]{32,80}", flags: "gi" },
  { type: "STRIPE_KEY", source: "sk_(?:live|test)_[a-zA-Z0-9]{20,}", flags: "g" },
  { type: "SLACK_TOKEN", source: "xox[bpras]-[a-zA-Z0-9\\-]{10,}", flags: "g" },
  { type: "GITHUB_PAT", source: "gh[pousr]_[a-zA-Z0-9]{36,}", flags: "g" },
  { type: "GITLAB_PAT", source: "glpat-[a-zA-Z0-9_\\-]{20,}", flags: "g" },
  { type: "PRIVATE_KEY", source: "-----BEGIN .* PRIVATE KEY-----", flags: "g" },
  {
    type: "JWT",
    source: "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
    flags: "g",
  },
  {
    type: "GENERIC_API_KEY",
    source: "(?:api[_\\s-]?key|apikey|api[_\\s-]?secret)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{16,}",
    flags: "gi",
  },
  {
    type: "GENERIC_TOKEN",
    source: "(?:token|bearer|auth[_\\s-]?token)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{16,}",
    flags: "gi",
  },
] as const;

/**
 * Redact all credential patterns in the given text.
 * Returns the text with credentials replaced by [REDACTED:TYPE].
 * Creates fresh regex instances per call to avoid stale lastIndex state.
 */
export function redactCredentials(text: string): string {
  let result = text;
  for (const { type, source, flags } of CREDENTIAL_PATTERNS) {
    const regex = new RegExp(source, flags);
    result = result.replace(regex, `[REDACTED:${type}]`);
  }
  return result;
}

/**
 * Check if text contains any credential patterns.
 */
export function containsCredentials(text: string): boolean {
  for (const { source, flags } of CREDENTIAL_PATTERNS) {
    const regex = new RegExp(source, flags);
    if (regex.test(text)) return true;
  }
  return false;
}
