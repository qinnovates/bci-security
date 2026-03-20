/**
 * Security module barrel export.
 *
 * Security architecture (defense in depth):
 *
 * Layer 1 — Input Validation (validator.ts)
 *   Zod schemas, max lengths, enum allowlists, control char stripping
 *
 * Layer 2 — Injection Detection (injection.ts)
 *   25 trigger phrases, NFKC normalization, throws on detection
 *
 * Layer 3 — Credential Redaction (credential-redactor.ts)
 *   10 regex patterns, applied at detection time, no opt-out
 *
 * Layer 4 — Output Sanitization (sanitizer.ts)
 *   8 rules, absolute path stripping, output injection filtering, self-verification pass
 *
 * Layer 5 — Path Guard (path-guard.ts)
 *   Data directory containment, traversal prevention, null byte rejection
 *
 * Layer 6 — Audit Logging (audit.ts)
 *   Structured stderr logging per MCP08:2025. Tool calls, errors, data poisoning alerts.
 *
 * Layer 7 — Data Integrity (loader.ts)
 *   File size limits (CWE-770), data poisoning scan (MCP03), startup validation
 *
 * Call order for tool handlers:
 *   1. Zod.parse(input)           — Layer 1
 *   2. assertNoInjection(fields)  — Layer 2
 *   3. redactCredentials(code)    — Layer 3 (at scan time)
 *   4. [tool logic]
 *   5. sanitizeReport(output)     — Layer 4 (includes output injection filter)
 *   6. auditToolCall(name, sizes) — Layer 6
 *
 * Path guard (Layer 5) is called by data/loader.ts at startup only.
 * Data integrity (Layer 7) runs once at startup.
 */

export { detectInjection, assertNoInjection } from "./injection.js";
export { redactCredentials, containsCredentials } from "./credential-redactor.js";
export { sanitizeReport } from "./sanitizer.js";
export type { SanitizeOptions } from "./sanitizer.js";
export { resolveDataPath, getDataDir } from "./path-guard.js";
export { audit, auditToolCall } from "./audit.js";
export {
  TaraLookupSchema,
  NissScoreSchema,
  BciScanSchema,
  BciComplianceSchema,
  BciThreatModelSchema,
  BciAnonymizeSchema,
  NeuromodestyCheckSchema,
  BciLearnSchema,
} from "./validator.js";
