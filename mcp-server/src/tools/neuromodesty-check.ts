/**
 * Neuromodesty Check tool — scan text for neuroethics overclaims.
 * Runs the 8 guardrails (G1-G8) against any text about BCI/neural systems.
 */

import { getGuardrails } from "../data/loader.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { NeuromodestyCheckInput } from "../security/validator.js";
import type { Guardrail, ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*Neuromodesty checks use pattern matching against published neuroethics guardrails " +
  "(Morse 2006, Poldrack 2006, Racine & Illes 2005, Ienca 2021, Kellmeyer 2022, Wexler 2019, " +
  "Tennison & Moreno 2012, Vul et al. 2009). False positives are expected. Always apply human judgment.*";

// Violation detection patterns for each guardrail
interface ViolationPattern {
  guardrailId: string;
  patterns: RegExp[];
}

const VIOLATION_PATTERNS: ViolationPattern[] = [
  {
    // G1: Neuromodesty — causal overclaims
    guardrailId: "G1",
    patterns: [
      /(?:brain|neural|cortical)\s+(?:activity|activation|signal)\s+(?:proves?|demonstrates?|shows? that|confirms?)\s+(?:cognitive|mental|psychological)/gi,
      /(?:thought|thinking|cognition|emotion)\s+(?:is|are)\s+(?:caused by|determined by|controlled by)\s+(?:brain|neural)/gi,
      /niss\s+(?:predicts?|diagnos|detects?\s+cognitive)/gi,
    ],
  },
  {
    // G2: Reverse Inference Fallacy
    guardrailId: "G2",
    patterns: [
      /activation\s+of\s+\w+\s+means?\s+(?:the\s+)?(?:person|subject|user|patient)\s+is\s+(?:experiencing|feeling|thinking)/gi,
      /(?:eeg|fmri|neural)\s+(?:data|signal|pattern)\s+(?:reads?|decodes?|reveals?)\s+(?:thought|intention|emotion|mental state)/gi,
    ],
  },
  {
    // G3: Neurorealism Triad
    guardrailId: "G3",
    patterns: [
      /brain\s+data\s+reveals?\s+(?:identity|who\s+(?:someone|a person)\s+is)/gi,
      /neural\s+(?:data|signal)\s+(?:is|are)\s+(?:a\s+)?(?:transparent|direct|complete)\s+(?:read-?out|window|mirror)/gi,
    ],
  },
  {
    // G4: Anti-Inflationism
    guardrailId: "G4",
    patterns: [
      /(?:we\s+)?need\s+(?:\d+\s+)?new\s+(?:neuro)?rights/gi,
      /(?:qif|niss|tara)\s+is\s+(?:the|a)\s+(?:first|only|definitive)\s+(?:open\s+)?standard/gi,
      /first[- ](?:ever|of[- ]its[- ]kind)\s+(?:framework|standard|mapping|catalog)/gi,
    ],
  },
  {
    // G5: Conceptual Underspecification
    guardrailId: "G5",
    patterns: [
      /(?:mental\s+privacy|mental\s+integrity|cognitive\s+liberty)\s+(?:is|means|requires|demands)/gi,
      /niss\s+(?:protects?|measures?|ensures?)\s+mental\s+(?:privacy|integrity)/gi,
    ],
  },
  {
    // G6: Brain Reading Limits
    guardrailId: "G6",
    patterns: [
      /(?:can|able\s+to)\s+read\s+(?:thoughts?|minds?|what\s+(?:someone|people)\s+(?:is|are)\s+thinking)/gi,
      /(?:bci|brain[- ]computer)\s+(?:can|will)\s+(?:decode|read|extract)\s+(?:thoughts?|memories|intentions)/gi,
    ],
  },
  {
    // G7: Dual-Use Trap
    guardrailId: "G7",
    patterns: [
      /(?:here'?s?\s+how\s+to|instructions?\s+for|guide\s+to)\s+(?:attack|hack|exploit|compromise)\s+(?:a\s+)?(?:bci|brain|neural)/gi,
    ],
  },
  {
    // G8: Statistical Inflation
    guardrailId: "G8",
    patterns: [
      /(?:neuroimaging|fmri|eeg)\s+(?:study|research|data)\s+proves?\s+(?:that\s+)?(?:bci|neural)/gi,
      /(?:brain\s+scan|neuroimaging)\s+(?:as\s+)?(?:ground\s+truth|definitive\s+evidence|conclusive\s+proof)/gi,
    ],
  },
];

// QIF status patterns — claims that QIF/TARA/NISS are standards or validated
const QIF_STATUS_VIOLATIONS = [
  /(?:qif|niss|tara|nsp|runemate)\s+(?:is|are)\s+(?:a\s+)?(?:validated|proven|certified|established|adopted)\s+(?:standard|framework|tool)/gi,
  /(?:qif|niss|tara)\s+(?:standard|specification)\b(?!\s*\(proposed)/gi,
];

function checkGuardrail(text: string, guardrail: Guardrail, patterns: RegExp[]): string[] {
  const violations: string[] = [];

  for (const pattern of patterns) {
    const fresh = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = fresh.exec(text)) !== null) {
      const start = Math.max(0, match.index - 30);
      const end = Math.min(text.length, match.index + match[0].length + 30);
      const context = text.slice(start, end).replace(/\n/g, " ");

      violations.push(
        `**${guardrail.id}: ${guardrail.name}** — "${context}"\n` +
          `  - Violation: ${guardrail.neuroethics.violation}\n` +
          `  - Correct: ${guardrail.neuroethics.correct}\n` +
          `  - Source: ${guardrail.source.author} (${guardrail.source.year})`
      );
    }
  }

  return violations;
}

export function neuromodestyCheck(input: NeuromodestyCheckInput): ToolResult {
  const guardrailData = getGuardrails();
  const allViolations: string[] = [];

  // Run all 8 guardrails
  for (const vp of VIOLATION_PATTERNS) {
    const guardrail = guardrailData.guardrails.find((g) => g.id === vp.guardrailId);
    if (!guardrail) continue;

    const violations = checkGuardrail(input.text, guardrail, vp.patterns);
    allViolations.push(...violations);
  }

  // QIF status checks
  if (input.include_qif_checks) {
    for (const pattern of QIF_STATUS_VIOLATIONS) {
      const fresh = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = fresh.exec(input.text)) !== null) {
        const start = Math.max(0, match.index - 30);
        const end = Math.min(input.text.length, match.index + match[0].length + 30);
        const context = input.text.slice(start, end).replace(/\n/g, " ");

        allViolations.push(
          `**QIF Status Violation** — "${context}"\n` +
            `  - QIF, NISS, TARA, NSP, and Runemate are all proposed, unvalidated, and in development.\n` +
            `  - Use "proposed framework," "research tool," or "in development." Never "standard," "validated," or "proven."`
        );
      }
    }
  }

  // Format report
  let report = `## Neuromodesty Check\n\n`;
  report += `**Text length:** ${input.text.length} characters\n`;
  report += `**QIF checks:** ${input.include_qif_checks ? "enabled" : "disabled"}\n\n`;

  if (allViolations.length === 0) {
    report +=
      "No neuromodesty violations detected.\n\n" +
      "**Note:** This check uses pattern matching. Subtle overclaims may not be caught. " +
      "Always apply the 6 neuromodesty checks manually for outward-facing text.\n";
  } else {
    report += `**${allViolations.length} violation(s) found:**\n\n`;
    for (let i = 0; i < allViolations.length; i++) {
      report += `${i + 1}. ${allViolations[i]}\n\n`;
    }
  }

  return {
    content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
  };
}
