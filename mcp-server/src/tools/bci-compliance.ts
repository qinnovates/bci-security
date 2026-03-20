/**
 * BCI Compliance tool — assess BCI systems against regulatory frameworks.
 */

import { getCompliance, getPii } from "../data/loader.js";
import { assertNoInjection } from "../security/injection.js";
import { redactCredentials } from "../security/credential-redactor.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { BciComplianceInput } from "../security/validator.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*This is a research tool for threat modeling, not legal advice. " +
  "Compliance mappings are simplified. Consult qualified legal counsel for compliance determinations. " +
  '"No issues detected" does not mean "compliant."*';

const FRAMEWORK_MAP: Record<string, string[]> = {
  all: [],
  gdpr: ["GDPR"],
  ccpa: ["CCPA"],
  chile: ["Chile"],
  unesco: ["UNESCO"],
  mind_act: ["Mind Act"],
  hipaa: ["HIPAA"],
};

export function bciCompliance(input: BciComplianceInput): ToolResult {
  const compliance = getCompliance();

  switch (input.mode) {
    case "frameworks": {
      let report = "## BCI Regulatory Compliance Frameworks\n\n";
      report += `**${compliance.compliance_domains.length} compliance domains** across 6 regulatory frameworks.\n\n`;

      for (const domain of compliance.compliance_domains) {
        report += `### ${domain.id}: ${domain.domain}\n`;
        report += `${domain.description}\n`;
        report += `- **Requirements:** ${domain.requirements.length}\n`;
        for (const req of domain.requirements) {
          report += `  - ${req.id}: ${req.requirement} (${req.severity})\n`;
        }
        report += "\n";
      }

      return {
        content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
      };
    }

    case "assess": {
      // System-level assessment based on compliance domains
      let report = "## BCI Compliance Assessment\n\n";
      report += "Answer the following questions for a system-level compliance assessment:\n\n";

      const questions = [
        "1. Is neural data classified as special category/sensitive data in your data classification policy?",
        "2. Is explicit informed consent obtained before neural data collection?",
        "3. Is separate consent obtained for cognitive state inference/classification?",
        "4. Can users withdraw consent and request data deletion?",
        "5. Is neural data collection limited to the stated purpose (data minimization)?",
        "6. Are neural data access controls role-based with audit logging?",
        "7. Is neural data encrypted at rest and in transit?",
        "8. Do you have a defined retention period for neural data?",
        "9. Are cross-border data transfers covered by adequacy decisions or SCCs?",
        "10. Is there an incident response plan specific to neural data breaches?",
      ];

      report += questions.join("\n") + "\n\n";
      report +=
        "Provide answers to get a compliance gap analysis. " +
        "Use `mode: scan` with code to detect technical compliance issues automatically.\n";

      return {
        content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
      };
    }

    case "scan": {
      if (!input.code) {
        return {
          content: [{ type: "text", text: "Scan mode requires the `code` parameter." }],
          isError: true,
        };
      }

      if (input.filename) {
        assertNoInjection(input.filename, "filename");
      }

      const code = redactCredentials(input.code);
      const pii = getPii();
      const frameworkFilter = FRAMEWORK_MAP[input.framework] ?? [];

      interface ComplianceFinding {
        pattern_id: string;
        name: string;
        severity: string;
        category: string;
        description: string;
        remediation: string;
        regulations: string[];
      }

      const findings: ComplianceFinding[] = [];

      // Run PII patterns against code
      for (const p of pii.patterns) {
        // Filter by framework if specified
        if (
          frameworkFilter.length > 0 &&
          !p.regulations.some((r) => frameworkFilter.some((f) => r.includes(f)))
        ) {
          continue;
        }

        try {
          const regex = new RegExp(p.pattern, "gi");
          if (regex.test(code)) {
            findings.push({
              pattern_id: p.id,
              name: p.name,
              severity: p.severity,
              category: pii.categories[p.category]?.label ?? p.category,
              description: p.description,
              remediation: p.remediation,
              regulations: p.regulations,
            });
          }
        } catch {
          // Skip patterns that don't compile
        }
      }

      // Check compliance domains
      const domainFindings: Array<{ domain: string; requirement: string; status: string }> = [];
      for (const domain of compliance.compliance_domains) {
        for (const req of domain.requirements) {
          if (
            frameworkFilter.length > 0 &&
            !req.regulations.some((r) => frameworkFilter.some((f) => r.includes(f)))
          ) {
            continue;
          }

          // Map PII findings to compliance requirements
          const relatedFindings = findings.filter((f) =>
            f.regulations.some((r) => req.regulations.includes(r))
          );

          if (relatedFindings.length > 0) {
            domainFindings.push({
              domain: `${domain.id}: ${domain.domain}`,
              requirement: `${req.id}: ${req.requirement}`,
              status: `ISSUE — ${relatedFindings.length} finding(s)`,
            });
          }
        }
      }

      // Format report
      let report =
        `## BCI Compliance Scan Results\n\n` +
        `**Scanned:** ${code.split("\n").length} lines` +
        `${input.filename ? ` (${input.filename})` : ""}\n` +
        `**Framework:** ${input.framework}\n` +
        `**Findings:** ${findings.length}\n\n`;

      if (findings.length === 0) {
        report +=
          "No compliance issues detected in the scanned code.\n\n" +
          '**Note:** "No issues detected" does not mean "compliant." ' +
          "This scan checks code patterns only, not organizational controls.\n";
      } else {
        report += "### PII & Data Protection Findings\n\n";
        for (const f of findings) {
          report +=
            `- **[${f.severity.toUpperCase()}] ${f.name}** (${f.pattern_id})\n` +
            `  - ${f.description}\n` +
            `  - Regulations: ${f.regulations.join(", ")}\n` +
            `  - Remediation: ${f.remediation}\n\n`;
        }

        if (domainFindings.length > 0) {
          report += "### Compliance Domain Impact\n\n";
          report += "| Domain | Requirement | Status |\n|--------|-------------|--------|\n";
          for (const d of domainFindings) {
            report += `| ${d.domain} | ${d.requirement} | ${d.status} |\n`;
          }
        }
      }

      return {
        content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: "Invalid mode. Use: scan, assess, or frameworks." }],
        isError: true,
      };
  }
}
