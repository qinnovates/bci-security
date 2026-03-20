/**
 * BCI Scan tool — scan code for BCI security anti-patterns.
 * Code is passed as a string argument. No file system access.
 */

import { getPii, getTara } from "../data/loader.js";
import { assertNoInjection } from "../security/injection.js";
import { redactCredentials, containsCredentials } from "../security/credentials.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { BciScanInput } from "../security/validator.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*This scan uses pattern matching (not static analysis). " +
  "False positives and false negatives are expected. " +
  "Not a substitute for professional security review.*";

// Neural data file extensions that trigger consent gate
const NEURAL_EXTENSIONS = [".edf", ".bdf", ".xdf", ".gdf", ".fif", ".nwb"];

// BCI library import patterns
const BCI_IMPORTS = [
  /(?:import|from)\s+(?:pylsl|brainflow|mne|pyedflib|nwalker)/,
  /require\s*\(\s*['"](?:pylsl|brainflow|mne|openbci)['"]\s*\)/,
  /#include\s*[<"](?:lsl_cpp|brainflow|openbci)/,
];

// Unencrypted transport patterns
const UNENCRYPTED_PATTERNS = [
  { pattern: /(?:http:\/\/|ws:\/\/)(?!localhost|127\.0\.0\.1)/gi, name: "Unencrypted HTTP/WS transport", tara: "QIF-T0003" },
  { pattern: /bluetooth(?!.*encrypt)/gi, name: "Bluetooth without encryption mention", tara: "QIF-T0003" },
  { pattern: /(?:tcp|udp)_(?:socket|connect|send)/gi, name: "Raw TCP/UDP socket", tara: "QIF-T0004" },
];

// Hardcoded credential patterns (additional to credentials.ts)
const HARDCODED_PATTERNS = [
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]+['"]/gi, name: "Hardcoded password" },
  { pattern: /(?:key|secret|token)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]/gi, name: "Hardcoded secret" },
];

interface Finding {
  severity: "critical" | "high" | "medium" | "info";
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

  // 1. Unencrypted transport
  for (const { pattern, name, tara } of UNENCRYPTED_PATTERNS) {
    const freshPattern = new RegExp(pattern.source, pattern.flags);
    const lines = code.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (freshPattern.test(lines[i])) {
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

  for (const { pattern, name } of HARDCODED_PATTERNS) {
    const freshPattern = new RegExp(pattern.source, pattern.flags);
    if (freshPattern.test(code)) {
      findings.push({
        severity: "critical",
        category: "Hardcoded Credentials",
        description: name,
        remediation: "Use environment variables or a secrets manager. Never hardcode credentials.",
      });
    }
  }

  // 3. PII patterns (only in BCI context)
  if (isBciCode || hasNeuralFile) {
    const pii = getPii();
    for (const p of pii.patterns) {
      try {
        const regex = new RegExp(p.pattern, "gi");
        if (regex.test(code)) {
          findings.push({
            severity: p.severity,
            category: "PII in BCI Pipeline",
            description: `${p.name} (${p.id})`,
            pattern_id: p.id,
            remediation: p.remediation,
          });
        }
      } catch {
        // Skip patterns that don't compile in JS regex engine
      }
    }
  }

  // 4. TARA technique mapping for findings
  const tara = getTara();
  const taraRefs = new Set(findings.map((f) => f.tara_ref).filter(Boolean));
  const relatedTechniques = tara.techniques.filter((t) => taraRefs.has(t.id));

  // Format output
  if (findings.length === 0) {
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

  const criticals = findings.filter((f) => f.severity === "critical").length;
  const highs = findings.filter((f) => f.severity === "high").length;
  const mediums = findings.filter((f) => f.severity === "medium").length;

  let report =
    `## BCI Security Scan Results\n\n` +
    `**Scanned:** ${code.split("\n").length} lines` +
    `${input.filename ? ` (${input.filename})` : ""}\n` +
    `**Findings:** ${findings.length} (${criticals} critical, ${highs} high, ${mediums} medium)\n\n`;

  // Group by severity
  for (const severity of ["critical", "high", "medium", "info"] as const) {
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
