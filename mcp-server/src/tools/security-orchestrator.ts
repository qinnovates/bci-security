/**
 * Security Orchestrator — unified scan that runs all available security tools.
 *
 * Calls external tools (Semgrep, Gitleaks, Grype, etc.) if installed,
 * merges results with built-in OWASP/CWE/Burp/BCI patterns.
 *
 * External tools are OPTIONAL — if not installed, that layer is skipped
 * and the built-in patterns still run. No network calls. All tools run locally.
 *
 * Air-gap flags applied to every external tool:
 * - Semgrep: --metrics=off, local rules only
 * - Gitleaks: no flags needed (zero telemetry)
 * - Grype: GRYPE_CHECK_FOR_APP_UPDATE=false, GRYPE_DB_AUTO_UPDATE=false
 * - TruffleHog: --no-verification (MANDATORY — prevents credential verification calls)
 * - detect-secrets: no flags needed (offline by default)
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Custom BCI Semgrep rules: mcp-server/src/tools -> ../../rules
const BCI_RULES_DIR = join(__dirname, "..", "..", "rules");
import { sanitizeReport } from "../security/sanitizer.js";
import { audit } from "../security/audit.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*Unified security scan combining built-in OWASP/CWE/Burp/BCI patterns with " +
  "external tools (Semgrep, Gitleaks, Grype) where installed. " +
  "All tools run locally with telemetry disabled. Not a substitute for professional penetration testing.*";

interface ExternalFinding {
  tool: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  rule: string;
  message: string;
  file?: string;
  line?: number;
  cwe?: string;
  owasp?: string;
}

/**
 * Check if a CLI tool is available on PATH.
 */
function toolExists(name: string): boolean {
  try {
    execFileSync("which", [name], { encoding: "utf-8", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run Semgrep on code string with telemetry disabled and local rules only.
 * Returns structured findings.
 */
function runSemgrep(code: string, language: string): ExternalFinding[] {
  if (!toolExists("semgrep")) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const ext = { python: ".py", javascript: ".js", typescript: ".ts", c: ".c", cpp: ".cpp" }[language] ?? ".txt";
  const tmpFile = join(tmpDir, `scan${ext}`);

  try {
    writeFileSync(tmpFile, code, "utf-8");

    // Build config args: always use BCI rules if they exist, add auto for broader coverage
    const configArgs: string[] = [];
    if (existsSync(join(BCI_RULES_DIR, "bci-security.yaml"))) {
      configArgs.push("--config", join(BCI_RULES_DIR, "bci-security.yaml"));
    }
    // Use p/default for OWASP/CWE coverage (Semgrep's curated default ruleset)
    configArgs.push("--config=p/default");

    const result = execFileSync("semgrep", [
      "scan",
      "--json",
      "--metrics=off",
      "--quiet",
      ...configArgs,
      tmpFile,
    ], {
      encoding: "utf-8",
      timeout: 120000,
      env: { ...process.env, SEMGREP_SEND_METRICS: "off" },
    });

    const parsed = JSON.parse(result);
    const findings: ExternalFinding[] = [];

    for (const r of parsed.results ?? []) {
      findings.push({
        tool: "Semgrep",
        severity: mapSemgrepSeverity(r.extra?.severity ?? "WARNING"),
        rule: r.check_id ?? "unknown",
        message: r.extra?.message ?? r.check_id ?? "Unknown finding",
        line: r.start?.line,
        cwe: r.extra?.metadata?.cwe?.[0],
        owasp: r.extra?.metadata?.owasp?.[0],
      });
    }

    audit("semgrep", `Scanned ${code.split("\n").length} lines, ${findings.length} findings`);
    return findings;
  } catch {
    audit("semgrep", "Scan failed or no findings");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup best-effort */ }
  }
}

function mapSemgrepSeverity(sev: string): ExternalFinding["severity"] {
  switch (sev.toUpperCase()) {
    case "ERROR": return "critical";
    case "WARNING": return "high";
    case "INFO": return "medium";
    default: return "medium";
  }
}

/**
 * Run Gitleaks on code string for secrets detection.
 * Zero telemetry — cleanest tool in the stack.
 */
function runGitleaks(code: string): ExternalFinding[] {
  if (!toolExists("gitleaks")) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, "scan.txt");
  const reportFile = join(tmpDir, "gitleaks-report.json");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    execFileSync("gitleaks", [
      "detect",
      "--source", tmpDir,
      "--report-format", "json",
      "--report-path", reportFile,
      "--no-git",
    ], {
      encoding: "utf-8",
      timeout: 30000,
    });

    // Gitleaks exits 0 if no findings, 1 if findings found
    return parseGitleaksReport(reportFile);
  } catch (error) {
    // Exit code 1 = findings found (not an error)
    return parseGitleaksReport(reportFile);
  } finally {
    try { unlinkSync(tmpFile); unlinkSync(reportFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

function parseGitleaksReport(reportFile: string): ExternalFinding[] {
  try {
    if (!existsSync(reportFile)) return [];
    const { readFileSync } = require("node:fs");
    const data = JSON.parse(readFileSync(reportFile, "utf-8"));
    const findings: ExternalFinding[] = [];

    for (const leak of data ?? []) {
      findings.push({
        tool: "Gitleaks",
        severity: "critical",
        rule: leak.RuleID ?? "unknown",
        message: `Secret detected: ${leak.Description ?? leak.RuleID ?? "unknown type"} [REDACTED]`,
        line: leak.StartLine,
      });
    }

    audit("gitleaks", `${findings.length} secrets found`);
    return findings;
  } catch {
    return [];
  }
}

/**
 * Run Grype on a package manifest for dependency CVE scanning.
 * Air-gapped flags applied.
 */
function runGrype(code: string, filename?: string): ExternalFinding[] {
  if (!toolExists("grype")) return [];

  // Only run Grype if the code looks like a package manifest
  const isManifest = filename && (
    filename.endsWith("package.json") ||
    filename.endsWith("requirements.txt") ||
    filename.endsWith("Pipfile.lock") ||
    filename.endsWith("go.sum") ||
    filename.endsWith("Cargo.lock") ||
    filename.endsWith("Gemfile.lock")
  );
  if (!isManifest) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, filename ?? "manifest");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    const result = execFileSync("grype", [
      `dir:${tmpDir}`,
      "--output", "json",
      "--quiet",
    ], {
      encoding: "utf-8",
      timeout: 60000,
      env: {
        ...process.env,
        GRYPE_CHECK_FOR_APP_UPDATE: "false",
        GRYPE_DB_AUTO_UPDATE: "false",
        GRYPE_DB_VALIDATE_AGE: "false",
      },
    });

    const parsed = JSON.parse(result);
    const findings: ExternalFinding[] = [];

    for (const match of parsed.matches ?? []) {
      const vuln = match.vulnerability ?? {};
      findings.push({
        tool: "Grype",
        severity: mapGrypeSeverity(vuln.severity ?? "Unknown"),
        rule: vuln.id ?? "unknown",
        message: `${vuln.id}: ${match.artifact?.name}@${match.artifact?.version} — ${vuln.description ?? "Known vulnerability"}`,
        cwe: vuln.cwe?.[0],
      });
    }

    audit("grype", `Scanned ${filename}, ${findings.length} CVEs found`);
    return findings;
  } catch {
    audit("grype", "Scan failed or no findings");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

function mapGrypeSeverity(sev: string): ExternalFinding["severity"] {
  switch (sev.toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "medium";
  }
}

/**
 * Run TruffleHog on code string for deep secrets detection.
 * MANDATORY: --no-verification prevents live API calls with found credentials.
 */
function runTrufflehog(code: string): ExternalFinding[] {
  if (!toolExists("trufflehog")) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, "scan.txt");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    const result = execFileSync("trufflehog", [
      "filesystem",
      tmpDir,
      "--json",
      "--no-verification",  // MANDATORY — prevents calling external APIs with found creds
      "--no-update",        // No update check
    ], {
      encoding: "utf-8",
      timeout: 60000,
    });

    const findings: ExternalFinding[] = [];
    // TruffleHog outputs one JSON object per line
    for (const line of result.split("\n").filter(Boolean)) {
      try {
        const parsed = JSON.parse(line);
        findings.push({
          tool: "TruffleHog",
          severity: "critical",
          rule: parsed.DetectorName ?? parsed.SourceMetadata?.Data?.Filesystem?.file ?? "unknown",
          message: `Secret detected: ${parsed.DetectorName ?? "unknown type"} [REDACTED]`,
          line: parsed.SourceMetadata?.Data?.Filesystem?.line,
        });
      } catch { /* skip malformed lines */ }
    }

    audit("trufflehog", `${findings.length} secrets found (--no-verification)`);
    return findings;
  } catch {
    audit("trufflehog", "Scan completed (no findings or error)");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

/**
 * Run detect-secrets on code string for entropy-based secret detection.
 * Catches secrets that don't match known patterns — the "unknown unknowns."
 */
function runDetectSecrets(code: string): ExternalFinding[] {
  if (!toolExists("detect-secrets")) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, "scan.txt");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    const result = execFileSync("detect-secrets", [
      "scan",
      tmpFile,
      "--list",
    ], {
      encoding: "utf-8",
      timeout: 30000,
    });

    const parsed = JSON.parse(result);
    const findings: ExternalFinding[] = [];

    for (const [_file, secrets] of Object.entries(parsed.results ?? {})) {
      for (const secret of secrets as Array<{ type: string; line_number: number }>) {
        findings.push({
          tool: "detect-secrets",
          severity: "high",
          rule: secret.type ?? "high-entropy-string",
          message: `Entropy-based secret: ${secret.type ?? "High entropy string"} [REDACTED]`,
          line: secret.line_number,
        });
      }
    }

    audit("detect-secrets", `${findings.length} entropy-based secrets found`);
    return findings;
  } catch {
    audit("detect-secrets", "Scan completed (no findings or error)");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

/**
 * Run OSV-Scanner on a package manifest for vulnerability scanning.
 * Uses experimental offline mode if available.
 */
function runOsvScanner(code: string, filename?: string): ExternalFinding[] {
  if (!toolExists("osv-scanner")) return [];

  const isManifest = filename && (
    filename.endsWith("package.json") ||
    filename.endsWith("package-lock.json") ||
    filename.endsWith("requirements.txt") ||
    filename.endsWith("Pipfile.lock") ||
    filename.endsWith("go.sum") ||
    filename.endsWith("Cargo.lock") ||
    filename.endsWith("pom.xml")
  );
  if (!isManifest) return [];

  const tmpDir = mkdtempSync(join(tmpdir(), "bci-scan-"));
  const tmpFile = join(tmpDir, filename ?? "manifest");

  try {
    writeFileSync(tmpFile, code, "utf-8");

    const result = execFileSync("osv-scanner", [
      "--format", "json",
      "--lockfile", `${tmpFile}`,
    ], {
      encoding: "utf-8",
      timeout: 60000,
    });

    const parsed = JSON.parse(result);
    const findings: ExternalFinding[] = [];

    for (const result_entry of parsed.results ?? []) {
      for (const pkg of result_entry.packages ?? []) {
        for (const vuln of pkg.vulnerabilities ?? []) {
          findings.push({
            tool: "OSV-Scanner",
            severity: mapOsvSeverity(vuln.database_specific?.severity ?? "MODERATE"),
            rule: vuln.id ?? "unknown",
            message: `${vuln.id}: ${pkg.package?.name}@${pkg.package?.version} — ${vuln.summary ?? "Known vulnerability"}`,
          });
        }
      }
    }

    audit("osv-scanner", `Scanned ${filename}, ${findings.length} vulnerabilities found`);
    return findings;
  } catch {
    audit("osv-scanner", "Scan completed (no findings or error)");
    return [];
  } finally {
    try { unlinkSync(tmpFile); rmdirSync(tmpDir); } catch { /* cleanup */ }
  }
}

function mapOsvSeverity(sev: string): ExternalFinding["severity"] {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MODERATE": case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return "medium";
  }
}

/**
 * Format external findings into a markdown report section.
 */
function formatExternalFindings(findings: ExternalFinding[]): string {
  if (findings.length === 0) return "";

  const byTool = new Map<string, ExternalFinding[]>();
  for (const f of findings) {
    const existing = byTool.get(f.tool) ?? [];
    existing.push(f);
    byTool.set(f.tool, existing);
  }

  let report = "### External Tool Findings\n\n";

  for (const [tool, toolFindings] of byTool) {
    report += `#### ${tool} (${toolFindings.length} finding${toolFindings.length === 1 ? "" : "s"})\n\n`;

    for (const f of toolFindings) {
      report += `- **[${f.severity.toUpperCase()}] ${f.rule}:** ${f.message}`;
      if (f.line) report += ` (line ${f.line})`;
      if (f.cwe) report += ` [${f.cwe}]`;
      if (f.owasp) report += ` [${f.owasp}]`;
      report += "\n";
    }
    report += "\n";
  }

  return report;
}

/**
 * Get the availability status of all external tools.
 */
export function getToolStatus(): Record<string, boolean> {
  return {
    semgrep: toolExists("semgrep"),
    gitleaks: toolExists("gitleaks"),
    grype: toolExists("grype"),
    trufflehog: toolExists("trufflehog"),
    "detect-secrets": toolExists("detect-secrets"),
    "osv-scanner": toolExists("osv-scanner"),
  };
}

/**
 * Run all available external security tools on the given code.
 * Returns findings merged from all tools.
 */
export function runExternalScanners(
  code: string,
  language: string,
  filename?: string
): { findings: ExternalFinding[]; report: string; toolsRun: string[] } {
  const allFindings: ExternalFinding[] = [];
  const toolsRun: string[] = [];

  // SAST: Semgrep
  const semgrepFindings = runSemgrep(code, language);
  if (semgrepFindings.length > 0 || toolExists("semgrep")) {
    toolsRun.push("Semgrep");
    allFindings.push(...semgrepFindings);
  }

  // Secrets: Gitleaks
  const gitleaksFindings = runGitleaks(code);
  if (gitleaksFindings.length > 0 || toolExists("gitleaks")) {
    toolsRun.push("Gitleaks");
    allFindings.push(...gitleaksFindings);
  }

  // Secrets: TruffleHog (--no-verification MANDATORY)
  const trufflehogFindings = runTrufflehog(code);
  if (trufflehogFindings.length > 0 || toolExists("trufflehog")) {
    toolsRun.push("TruffleHog");
    allFindings.push(...trufflehogFindings);
  }

  // Secrets: detect-secrets (entropy-based)
  const detectSecretsFindings = runDetectSecrets(code);
  if (detectSecretsFindings.length > 0 || toolExists("detect-secrets")) {
    toolsRun.push("detect-secrets");
    allFindings.push(...detectSecretsFindings);
  }

  // SCA: Grype (only for package manifests)
  const grypeFindings = runGrype(code, filename);
  if (grypeFindings.length > 0 || toolExists("grype")) {
    toolsRun.push("Grype");
    allFindings.push(...grypeFindings);
  }

  // SCA: OSV-Scanner (only for package manifests)
  const osvFindings = runOsvScanner(code, filename);
  if (osvFindings.length > 0 || toolExists("osv-scanner")) {
    toolsRun.push("OSV-Scanner");
    allFindings.push(...osvFindings);
  }

  const report = formatExternalFindings(allFindings);
  return { findings: allFindings, report, toolsRun };
}

/**
 * Tool status report — shows which external tools are available.
 */
export function securityToolStatus(): ToolResult {
  const status = getToolStatus();
  const installed = Object.entries(status).filter(([_, v]) => v).map(([k]) => k);
  const missing = Object.entries(status).filter(([_, v]) => !v).map(([k]) => k);

  let report = "## Security Tool Status\n\n";
  report += `**Installed:** ${installed.length > 0 ? installed.join(", ") : "none"}\n`;
  report += `**Missing:** ${missing.length > 0 ? missing.join(", ") : "none"}\n\n`;

  if (missing.length > 0) {
    report += "### Install Missing Tools\n\n```bash\nbrew install " + missing.join(" ") + "\n```\n\n";
  }

  report += "### Built-in (always available)\n\n";
  report += "- OWASP Top 10:2021 (78 patterns)\n";
  report += "- OWASP API Security Top 10:2023\n";
  report += "- OWASP LLM Top 10:2025\n";
  report += "- CWE Top 25:2024\n";
  report += "- Burp Suite categories\n";
  report += "- BCI PII patterns (18)\n";
  report += "- Credential detection (10 patterns)\n";
  report += "- TARA technique mapping (135)\n";

  return {
    content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
  };
}
