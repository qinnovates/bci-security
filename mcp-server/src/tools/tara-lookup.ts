/**
 * TARA Lookup tool — search and retrieve BCI threat techniques from the TARA catalog.
 */

import { getTara } from "../data/loader.js";
import { assertNoInjection } from "../security/injection.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { TaraLookupInput } from "../security/validator.js";
import type { TaraTechnique, ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*TARA is a proposed research catalog (unvalidated, in development). " +
  "Not a substitute for professional security assessment. " +
  "Threat descriptions are for defensive purposes only.*";

function formatTechnique(t: TaraTechnique): string {
  const lines = [
    `### ${t.id}: ${t.name}`,
    `- **Status:** ${t.status}`,
    `- **Tactic:** ${t.tactic}`,
    `- **Bands:** ${t.bands}`,
    `- **Tactical Severity:** ${t.severity}`,
    `- **NISS Score:** ${t.niss.score} (${t.niss.severity}) — ${t.niss.vector}`,
    `- **Mechanism:** ${t.mechanism}`,
    `- **Sources:** ${t.sources.join(", ")}`,
    `- **Dual-Use:** ${t.dual_use}${t.therapeutic_analog ? ` (therapeutic analog: ${t.therapeutic_analog})` : ""}`,
    `- **Mitigations:** ${t.mitigations.join(", ")}`,
  ];
  return lines.join("\n");
}

export function taraLookup(input: TaraLookupInput): ToolResult {
  assertNoInjection(input.query, "query");

  const tara = getTara();
  const query = input.query.toLowerCase();
  let results: TaraTechnique[];

  switch (input.search_by) {
    case "id": {
      // Validate ID format: QIF-T0001 or T0001
      const idQuery = query.replace(/^qif-/, "").replace(/^t/, "qif-t").toUpperCase();
      const normalized = query.startsWith("qif-") ? query.toUpperCase() : `QIF-${query.toUpperCase()}`;
      results = tara.techniques.filter(
        (t) => t.id === normalized || t.id === idQuery || t.id.toUpperCase() === query.toUpperCase()
      );
      break;
    }
    case "severity":
      results = tara.techniques.filter((t) => t.severity === query || t.niss.severity === query);
      break;
    case "status":
      results = tara.techniques.filter((t) => t.status.toLowerCase() === query);
      break;
    case "tactic":
      results = tara.techniques.filter((t) => t.tactic.toLowerCase().includes(query));
      break;
    case "band":
      results = tara.techniques.filter((t) => t.bands.toLowerCase().includes(query));
      break;
    case "keyword":
    default:
      results = tara.techniques.filter(
        (t) =>
          t.name.toLowerCase().includes(query) ||
          t.mechanism.toLowerCase().includes(query) ||
          t.tactic.toLowerCase().includes(query) ||
          t.mitigations.some((m) => m.toLowerCase().includes(query))
      );
      break;
  }

  const limited = results.slice(0, input.limit);
  const total = results.length;

  if (limited.length === 0) {
    return {
      content: [
        {
          type: "text",
          text: sanitizeReport(
            `No TARA techniques found for "${input.query}" (searched by: ${input.search_by}).` +
              `\n\nCatalog contains ${tara.total} techniques. Try a broader keyword or different search_by mode.` +
              DISCLAIMER
          ),
        },
      ],
    };
  }

  const header = `## TARA Lookup: "${input.query}" (by ${input.search_by})\n\n` +
    `Found ${total} technique(s)${total > input.limit ? ` (showing first ${input.limit})` : ""}:\n\n`;

  const body = limited.map(formatTechnique).join("\n\n");

  return {
    content: [{ type: "text", text: sanitizeReport(header + body + DISCLAIMER) }],
  };
}
