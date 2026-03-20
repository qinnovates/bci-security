/**
 * BCI Anonymize tool — detect PII in neural data content/metadata.
 * Operates on strings only. No file system access.
 */

import { getPii } from "../data/loader.js";
import { assertNoInjection } from "../security/injection.js";
import { redactCredentials } from "../security/credential-redactor.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { BciAnonymizeInput } from "../security/validator.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*PII detection uses pattern matching. False positives and false negatives are expected. " +
  "Always perform manual review before sharing neural data. " +
  "Not a substitute for professional data protection assessment.*";

const CONSENT_TEMPLATE = `{
  "consent_version": "1.0",
  "subject_id": "sub-001",
  "consent_type": "informed",
  "purpose": "[SPECIFY: research / clinical / commercial]",
  "data_types": ["eeg", "metadata"],
  "processing_operations": ["recording", "analysis"],
  "date_obtained": "YYYY-MM-DD",
  "data_controller": "[ORGANIZATION]",
  "retention_period": "[SPECIFY: e.g., 5 years post-study]",
  "right_to_withdraw": true,
  "withdrawal_contact": "[CONTACT INFO]",
  "third_party_sharing": false,
  "cross_border_transfer": false,
  "automated_decision_making": false
}`;

const BIDS_TEMPLATE = `# BIDS Directory Structure for Anonymized Neural Data

project/
├── dataset_description.json    # Required: project metadata
├── participants.tsv           # Anonymized subject list
├── participants.json          # Column descriptions
├── sub-001/
│   └── eeg/
│       ├── sub-001_task-rest_eeg.edf      # Anonymized filename
│       ├── sub-001_task-rest_eeg.json      # Sidecar metadata
│       ├── sub-001_task-rest_channels.tsv  # Channel info
│       └── sub-001_task-rest_events.tsv    # Event markers
└── sub-002/
    └── eeg/
        └── ...`;

export function bciAnonymize(input: BciAnonymizeInput): ToolResult {
  if (input.filename) {
    assertNoInjection(input.filename, "filename");
  }

  switch (input.mode) {
    case "template": {
      const report =
        `## BCI Data Anonymization Templates\n\n` +
        `### Consent Sidecar Template (.consent.json)\n\n\`\`\`json\n${CONSENT_TEMPLATE}\n\`\`\`\n\n` +
        `### BIDS Directory Structure\n\n\`\`\`\n${BIDS_TEMPLATE}\n\`\`\`\n\n` +
        `### Anonymization Checklist\n\n` +
        `- [ ] Remove subject names from filenames\n` +
        `- [ ] Clear patient/subject fields in file headers\n` +
        `- [ ] Remove dates of birth and recording dates (keep age range if needed)\n` +
        `- [ ] Strip device serial numbers or hash them\n` +
        `- [ ] Remove IP addresses and location data\n` +
        `- [ ] Create .consent.json sidecar for each recording\n` +
        `- [ ] Verify no PII in event markers or annotations\n` +
        `- [ ] Consider brainwave signature re-identification risk\n`;

      return {
        content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
      };
    }

    case "check": {
      // Check filename only for PII
      if (!input.filename) {
        return {
          content: [{ type: "text", text: "Check mode requires the `filename` parameter." }],
          isError: true,
        };
      }

      const pii = getPii();
      const findings: Array<{ id: string; name: string; severity: string; remediation: string }> = [];

      for (const p of pii.patterns) {
        if (!p.context.includes("filename")) continue;
        try {
          const regex = new RegExp(p.pattern, "gi");
          if (regex.test(input.filename)) {
            findings.push({
              id: p.id,
              name: p.name,
              severity: p.severity,
              remediation: p.remediation,
            });
          }
          // Also check broad pattern if present
          if (p.pattern_broad) {
            const broadRegex = new RegExp(p.pattern_broad, "g");
            if (broadRegex.test(input.filename)) {
              findings.push({
                id: `${p.id}-broad`,
                name: `${p.name} (broad match)`,
                severity: p.severity,
                remediation: p.remediation,
              });
            }
          }
        } catch {
          // Skip
        }
      }

      let report = `## Filename PII Check: ${input.filename}\n\n`;
      if (findings.length === 0) {
        report += "No PII patterns detected in filename.\n";
      } else {
        report += `**${findings.length} issue(s) found:**\n\n`;
        for (const f of findings) {
          report +=
            `- **[${f.severity.toUpperCase()}] ${f.name}** (${f.id})\n` +
            `  - Remediation: ${f.remediation}\n`;
        }
      }

      return {
        content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
      };
    }

    case "scan": {
      if (!input.content) {
        return {
          content: [{ type: "text", text: "Scan mode requires the `content` parameter." }],
          isError: true,
        };
      }

      // Redact credentials immediately
      const content = redactCredentials(input.content);
      const pii = getPii();
      const findings: Array<{
        id: string;
        name: string;
        severity: string;
        category: string;
        remediation: string;
        regulations: string[];
      }> = [];

      for (const p of pii.patterns) {
        try {
          const regex = new RegExp(p.pattern, "gi");
          if (regex.test(content)) {
            findings.push({
              id: p.id,
              name: p.name,
              severity: p.severity,
              category: pii.categories[p.category]?.label ?? p.category,
              remediation: p.remediation,
              regulations: p.regulations,
            });
          }
        } catch {
          // Skip
        }
      }

      let report =
        `## BCI Data Anonymization Scan\n\n` +
        `**Format:** ${input.format ?? "unknown"}\n` +
        `**Content length:** ${content.length} characters\n` +
        `**Findings:** ${findings.length}\n\n`;

      if (findings.length === 0) {
        report += "No PII patterns detected in the provided content.\n";
      } else {
        const bySeverity = ["critical", "high", "medium"] as const;
        for (const sev of bySeverity) {
          const group = findings.filter((f) => f.severity === sev);
          if (group.length === 0) continue;

          report += `### ${sev.toUpperCase()}\n\n`;
          for (const f of group) {
            report +=
              `- **${f.name}** (${f.id}, ${f.category})\n` +
              `  - Regulations: ${f.regulations.join(", ")}\n` +
              `  - Remediation: ${f.remediation}\n`;
          }
          report += "\n";
        }
      }

      return {
        content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: "Invalid mode. Use: scan, check, or template." }],
        isError: true,
      };
  }
}
