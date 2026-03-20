/**
 * NISS Score tool — look up and explain Neural Impact Severity Scores.
 */

import { getTara, getNissDevices } from "../data/loader.js";
import { assertNoInjection } from "../security/injection.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { NissScoreInput } from "../security/validator.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*NISS is a proposed scoring system (unvalidated, in development). " +
  "Scores measure signal-level disruption, not cognitive or mental states. " +
  "Not a clinical diagnostic instrument.*";

const NISS_EXPLANATION = `## NISS Vector Format

**NISS:1.1/BI:X/CR:X/CD:X/CV:X/RV:X/NP:X**

| Dimension | Meaning | Scale |
|-----------|---------|-------|
| BI | Biological Impact | N(one), L(ow), M(ed), H(igh) |
| CR | Coupling Risk | N, L, M, H |
| CD | Coherence Disruption | N, L, M, H |
| CV | Consent Violation | N(one), I(mplied), E(xplicit) |
| RV | Reversibility | F(ull), P(artial), I(rreversible) |
| NP | Neuroplasticity Risk | N(one), T(ransient), P(ermanent) |

**Score Range:** 0.0 (no impact) to 10.0 (catastrophic)
**Severity Bands:** None (0), Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0)

NISS measures physical signal disruption at the electrode-tissue-network level. It does NOT measure "thought harm," mental states, or cognitive content.`;

export function nissScore(input: NissScoreInput): ToolResult {
  assertNoInjection(input.query, "query");

  switch (input.mode) {
    case "explain":
      return {
        content: [{ type: "text", text: sanitizeReport(NISS_EXPLANATION + DISCLAIMER) }],
      };

    case "device": {
      const devices = getNissDevices();
      const query = input.query.toLowerCase();
      const matches = devices.devices.filter(
        (d) => d.device.toLowerCase().includes(query) || d.type.toLowerCase() === query
      );

      if (matches.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: sanitizeReport(
                `No devices found matching "${input.query}". ` +
                  `Available devices: ${devices.devices.map((d) => d.device).join(", ")}` +
                  DISCLAIMER
              ),
            },
          ],
        };
      }

      const body = matches
        .map(
          (d) =>
            `### ${d.device}\n` +
            `- **Type:** ${d.type} | **Purpose:** ${d.purpose}\n` +
            `- **Overall Score:** ${d.overall_score} (${d.severity})\n` +
            `- **Vector:** ${d.vector}\n` +
            `- **Applicable Techniques:** ${d.n_techniques}\n` +
            `- **Subscores:** ${Object.entries(d.subscores)
              .map(([k, v]) => `${k}: ${v}`)
              .join(", ")}`
        )
        .join("\n\n");

      return {
        content: [
          {
            type: "text",
            text: sanitizeReport(`## NISS Device Scores: "${input.query}"\n\n${body}${DISCLAIMER}`),
          },
        ],
      };
    }

    case "compare": {
      // Compare expects "A vs B" format
      const parts = input.query.split(/\s+vs\s+/i);
      if (parts.length !== 2) {
        return {
          content: [
            {
              type: "text",
              text: 'Compare mode expects "A vs B" format. Example: "Neuralink N1 vs Muse 2"',
            },
          ],
          isError: true,
        };
      }
      const devices = getNissDevices();
      const [a, b] = parts.map((p) => p.trim().toLowerCase());
      const deviceA = devices.devices.find((d) => d.device.toLowerCase().includes(a));
      const deviceB = devices.devices.find((d) => d.device.toLowerCase().includes(b));

      if (!deviceA || !deviceB) {
        const missing = [!deviceA ? parts[0] : null, !deviceB ? parts[1] : null]
          .filter(Boolean)
          .join(", ");
        return {
          content: [{ type: "text", text: `Device(s) not found: ${missing}` }],
          isError: true,
        };
      }

      const body =
        `## NISS Comparison: ${deviceA.device} vs ${deviceB.device}\n\n` +
        `| Dimension | ${deviceA.device} | ${deviceB.device} |\n` +
        `|-----------|${"-".repeat(deviceA.device.length + 2)}|${"-".repeat(deviceB.device.length + 2)}|\n` +
        `| Overall | ${deviceA.overall_score} (${deviceA.severity}) | ${deviceB.overall_score} (${deviceB.severity}) |\n` +
        Object.keys(deviceA.subscores)
          .map(
            (k) =>
              `| ${k} | ${deviceA.subscores[k]} | ${deviceB.subscores[k] ?? "N/A"} |`
          )
          .join("\n") +
        `\n| Type | ${deviceA.type} | ${deviceB.type} |` +
        `\n| Purpose | ${deviceA.purpose} | ${deviceB.purpose} |`;

      return {
        content: [{ type: "text", text: sanitizeReport(body + DISCLAIMER) }],
      };
    }

    case "technique":
    default: {
      const tara = getTara();
      const query = input.query.toLowerCase();
      const matches = tara.techniques.filter(
        (t) =>
          t.id.toLowerCase() === query ||
          t.id.toLowerCase() === `qif-${query}` ||
          t.name.toLowerCase().includes(query)
      );

      if (matches.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: sanitizeReport(
                `No techniques found matching "${input.query}". ` +
                  `Try searching by technique ID (e.g., "T0001") or keyword.` +
                  DISCLAIMER
              ),
            },
          ],
        };
      }

      const body = matches
        .map(
          (t) =>
            `### ${t.id}: ${t.name}\n` +
            `- **NISS Score:** ${t.niss.score} (${t.niss.severity})\n` +
            `- **Vector:** ${t.niss.vector}\n` +
            `- **Tactical Severity:** ${t.severity}\n` +
            `- **Note:** Tactical severity and NISS severity may differ. Tactical = "how bad if it succeeds." NISS = "biological signal disruption level."`
        )
        .join("\n\n");

      return {
        content: [
          {
            type: "text",
            text: sanitizeReport(`## NISS Scores: "${input.query}"\n\n${body}${DISCLAIMER}`),
          },
        ],
      };
    }
  }
}
