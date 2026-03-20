/**
 * BCI Scan tool — scan code for BCI security anti-patterns.
 * Code is passed as a string argument. No file system access.
 */

import { getPii, getTara, getSecurityScanPatterns } from "../data/loader.js";
import { assertNoInjection } from "../security/injection.js";
import { redactCredentials, containsCredentials } from "../security/credential-redactor.js";
import { sanitizeReport } from "../security/sanitizer.js";
import { safeRegexTest } from "../security/safe-regex.js";
import { runExternalScanners } from "./security-orchestrator.js";
import type { BciScanInput } from "../security/validator.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*This scan uses pattern matching against OWASP Top 10:2021, OWASP API Security Top 10:2023, " +
  "OWASP LLM Top 10:2025, CWE Top 25:2024, Burp Suite categories, and BCI-specific threat patterns. " +
  "Not static analysis. False positives and false negatives are expected. " +
  "Not a substitute for professional security review or full SAST (e.g., Semgrep).*";

// Neural data file extensions that trigger consent gate
const NEURAL_EXTENSIONS = [".edf", ".bdf", ".xdf", ".gdf", ".fif", ".nwb"];

// BCI library import patterns
const BCI_IMPORTS = [
  /(?:import|from)\s+(?:pylsl|brainflow|mne|pyedflib|nwalker)/,
  /require\s*\(\s*['"](?:pylsl|brainflow|mne|openbci)['"]\s*\)/,
  /#include\s*[<"](?:lsl_cpp|brainflow|openbci)/,
];

// Unencrypted transport patterns (string-based for safeRegexTest)
const UNENCRYPTED_PATTERNS = [
  { source: "(?:http:\\/\\/|ws:\\/\\/)(?!localhost|127\\.0\\.0\\.1)", flags: "gi", name: "Unencrypted HTTP/WS transport", tara: "QIF-T0003" },
  { source: "bluetooth(?!.*encrypt)", flags: "gi", name: "Bluetooth without encryption mention", tara: "QIF-T0003" },
  { source: "(?:tcp|udp)_(?:socket|connect|send)", flags: "gi", name: "Raw TCP/UDP socket", tara: "QIF-T0004" },
];

// Hardcoded credential patterns (string-based for safeRegexTest)
const HARDCODED_PATTERNS = [
  { source: "(?:password|passwd|pwd)\\s*[:=]\\s*['\"][^'\"]+['\"]", flags: "gi", name: "Hardcoded password" },
  { source: "(?:key|secret|token)\\s*[:=]\\s*['\"][A-Za-z0-9+/=]{16,}['\"]", flags: "gi", name: "Hardcoded secret" },
];

interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  line?: number;
  pattern_id?: string;
  tara_ref?: string;
  remediation: string;
}

export function bciScan(input: BciScanInput): ToolResult {
  if (input.filename) {
    assertNoInjection(input.filename, "filename");
  }

  // Redact credentials immediately — SAFETY.md Section 3
  const code = redactCredentials(input.code);
  const findings: Finding[] = [];

  // Check if this is BCI code
  const isBciCode = BCI_IMPORTS.some((p) => p.test(code));
  const hasNeuralFile =
    input.filename !== undefined &&
    NEURAL_EXTENSIONS.some((ext) => input.filename!.toLowerCase().endsWith(ext));

  // Consent gate check
  if (hasNeuralFile) {
    findings.push({
      severity: "info",
      category: "Consent Gate",
      description:
        "Neural data file detected. Confirm: these files do not contain real patient/subject data, " +
        "OR your organization's data handling agreements cover AI-assisted analysis.",
      remediation: "Verify consent before processing neural data.",
    });
  }

  // 1. Unencrypted transport — uses safeRegexTest
  const lines = code.split("\n");
  for (const { source, flags, name, tara } of UNENCRYPTED_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (safeRegexTest(source, flags, lines[i])) {
        findings.push({
          severity: "high",
          category: "Unencrypted Transport",
          description: `${name} detected`,
          line: i + 1,
          tara_ref: tara,
          remediation: "Use HTTPS/WSS for all external connections. Encrypt BLE communications.",
        });
      }
    }
  }

  // 2. Credential detection
  if (containsCredentials(input.code)) {
    findings.push({
      severity: "critical",
      category: "Exposed Credentials",
      description: "Credentials detected in code (redacted in output)",
      remediation: "Move credentials to environment variables or a secrets manager.",
    });
  }

  for (const { source, flags, name } of HARDCODED_PATTERNS) {
    if (safeRegexTest(source, flags, code)) {
      findings.push({
        severity: "critical",
        category: "Hardcoded Credentials",
        description: name,
        remediation: "Use environment variables or a secrets manager. Never hardcode credentials.",
      });
    }
  }

  // 3. PII patterns (only in BCI context) — uses safeRegexTest (CWE-1333 mitigated)
  if (isBciCode || hasNeuralFile) {
    const pii = getPii();
    for (const p of pii.patterns) {
      if (safeRegexTest(p.pattern, "gi", code)) {
        findings.push({
          severity: p.severity,
          category: "PII in BCI Pipeline",
          description: `${p.name} (${p.id})`,
          pattern_id: p.id,
          remediation: p.remediation,
        });
      }
    }
  }

  // 4. OWASP / CWE / Burp Suite patterns (all code, not just BCI)
  const secPatterns = getSecurityScanPatterns();
  const langMap: Record<string, string> = {
    python: "python",
    javascript: "javascript",
    typescript: "typescript",
    c: "c",
    cpp: "cpp",
    matlab: "unknown",
    unknown: "unknown",
  };
  const lang = langMap[input.language] ?? "unknown";

  for (const p of secPatterns.patterns) {
    // Filter by language — run pattern if it applies to this language or if language is unknown
    if (lang !== "unknown" && !p.context.includes(lang)) continue;

    // Uses safeRegexTest — patterns validated at startup (CWE-1333 mitigated)
    if (safeRegexTest(p.pattern, "gi", code)) {
      const categoryLabel = secPatterns.categories[p.category]?.label ?? p.category;
      findings.push({
        severity: p.severity,
        category: `${categoryLabel}: ${p.name}`,
        description: `${p.description} [${p.cwe}${p.owasp ? `, ${p.owasp}` : ""}]`,
        pattern_id: p.id,
        remediation: p.remediation,
      });
    }
  }

  // 5. External tool scanners (Semgrep, Gitleaks, Grype — if installed)
  const external = runExternalScanners(input.code, input.language, input.filename);

  // 6. TARA technique mapping for findings
  const tara = getTara();
  const taraRefs = new Set(findings.map((f) => f.tara_ref).filter(Boolean));
  const relatedTechniques = tara.techniques.filter((t) => taraRefs.has(t.id));

  // Total finding count includes external
  const totalFindings = findings.length + external.findings.length;

  // Format output
  if (totalFindings === 0) {
    return {
      content: [
        {
          type: "text",
          text: sanitizeReport(
            `## BCI Security Scan: No Issues Found\n\n` +
              `Scanned ${code.split("\n").length} lines` +
              `${input.filename ? ` (${input.filename})` : ""}. ` +
              `No BCI security anti-patterns detected.\n\n` +
              `**Note:** "No issues detected" does not mean "secure." This scan uses pattern matching only.` +
              DISCLAIMER
          ),
        },
      ],
    };
  }

  const allSeverities = [
    ...findings.map((f) => f.severity),
    ...external.findings.map((f) => f.severity),
  ];
  const criticals = allSeverities.filter((s) => s === "critical").length;
  const highs = allSeverities.filter((s) => s === "high").length;
  const mediums = allSeverities.filter((s) => s === "medium").length;

  let report =
    `## Security Scan Results\n\n` +
    `**Scanned:** ${code.split("\n").length} lines` +
    `${input.filename ? ` (${input.filename})` : ""}\n` +
    `**Built-in findings:** ${findings.length} | **External tool findings:** ${external.findings.length}\n` +
    `**Total:** ${totalFindings} (${criticals} critical, ${highs} high, ${mediums} medium)\n` +
    `**Tools run:** Built-in OWASP/CWE/Burp/BCI${external.toolsRun.length > 0 ? ` + ${external.toolsRun.join(", ")}` : ""}\n\n`;

  // Group by severity
  for (const severity of ["critical", "high", "medium", "low", "info"] as const) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;

    report += `### ${severity.toUpperCase()}\n\n`;
    for (const f of group) {
      report += `- **${f.category}:** ${f.description}`;
      if (f.line) report += ` (line ${f.line})`;
      if (f.tara_ref) report += ` [${f.tara_ref}]`;
      report += `\n  - Remediation: ${f.remediation}\n`;
    }
    report += "\n";
  }

  // External tool findings
  if (external.report) {
    report += external.report;
  }

  if (relatedTechniques.length > 0) {
    report += `### Related TARA Techniques\n\n`;
    for (const t of relatedTechniques) {
      report += `- **${t.id}:** ${t.name} (NISS: ${t.niss.score}, ${t.niss.severity})\n`;
    }
  }

  return {
    content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
  };
}
