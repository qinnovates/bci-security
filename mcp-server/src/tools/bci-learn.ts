/**
 * BCI Learn tool — interactive educational walkthroughs for BCI security concepts.
 */

import { getTara, getGuardrails } from "../data/loader.js";
import { sanitizeReport } from "../security/sanitizer.js";
import type { BciLearnInput } from "../security/validator.js";
import type { ToolResult } from "../types/index.js";

const DISCLAIMER =
  "\n\n---\n*Educational content based on the QIF proposed research framework (unvalidated, in development). " +
  "For learning purposes only.*";

interface LessonStep {
  title: string;
  content: string;
  next?: string;
}

function getQuickstart(step: number): LessonStep {
  const steps: LessonStep[] = [
    {
      title: "What is BCI Security?",
      content:
        "Brain-Computer Interfaces (BCIs) read neural signals (EEG, ECoG, LFP) and " +
        "sometimes write back (neurostimulation). BCI security is the applied engineering " +
        "discipline of protecting these systems from unauthorized access, manipulation, " +
        "and data theft.\n\n" +
        "Key difference from IT security: BCIs interface directly with biological neural tissue. " +
        "A compromised BCI can cause physical harm, not just data loss.",
      next: "Step 2: The QIF Hourglass Model",
    },
    {
      title: "The QIF Hourglass Model",
      content:
        "QIF maps BCI systems across 11 bands in an hourglass shape:\n\n" +
        "**Neural bands (N7-N1):** From higher cognition down to spinal reflexes\n" +
        "**Interface band (I0):** The electrode-tissue boundary\n" +
        "**Silicon bands (S1-S3):** From analog hardware to cloud infrastructure\n\n" +
        "The interface band (I0) is the critical boundary. Security controls must exist " +
        "on both sides of this boundary.",
      next: "Step 3: Threat Techniques (TARA)",
    },
    {
      title: "Threat Techniques (TARA)",
      content:
        "TARA is a proposed catalog of BCI threat techniques. " +
        "Each technique describes a specific attack method, the QIF bands it spans, " +
        "and its severity.\n\n" +
        "Try using the `tara_lookup` tool to explore techniques. " +
        'Example: search for "signal injection" or look up "QIF-T0001".',
      next: "Step 4: Severity Scoring (NISS)",
    },
    {
      title: "Severity Scoring (NISS)",
      content:
        "NISS is a proposed 6-dimensional scoring system for BCI threats.\n\n" +
        "Unlike CVSS (which scores IT vulnerabilities), NISS adds dimensions specific to " +
        "neural systems: Biological Impact, Coupling Risk, Coherence Disruption, " +
        "Consent Violation, Reversibility, and Neuroplasticity Risk.\n\n" +
        "Try the `niss_score` tool with `mode: explain` for the full vector format.",
      next: "Step 5: Neuroethics Guardrails",
    },
    {
      title: "Neuroethics Guardrails",
      content:
        "BCI security must operate within ethical constraints. 8 guardrails from " +
        "published neuroethics literature define what the framework can and cannot claim.\n\n" +
        "The most important: **Neuromodesty** (Morse 2006) — neural correlates do not " +
        "prove causation. We score signal disruption, not 'thought harm.'\n\n" +
        "Try the `neuromodesty_check` tool to scan text for overclaims.",
    },
  ];

  const idx = Math.min(step - 1, steps.length - 1);
  return steps[idx];
}

function getTaraLesson(step: number): LessonStep {
  const tara = getTara();
  const confirmed = tara.techniques.filter((t) => t.status === "CONFIRMED");
  const emerging = tara.techniques.filter((t) => t.status === "EMERGING");

  const steps: LessonStep[] = [
    {
      title: "TARA Overview",
      content:
        `The TARA catalog contains ${tara.total} threat techniques.\n\n` +
        `**By status:**\n` +
        `- CONFIRMED: ${confirmed.length} (demonstrated in published research)\n` +
        `- EMERGING: ${emerging.length} (technically feasible, limited evidence)\n` +
        `- Other statuses: DEMONSTRATED, PROJECTED, THEORETICAL\n\n` +
        `Each technique has: ID, name, tactic, bands, status, severity, NISS score, mechanism, sources, and mitigations.`,
      next: "Step 2: Tactics",
    },
    {
      title: "TARA Tactics",
      content:
        "TARA organizes techniques by tactic (the attacker's goal):\n\n" +
        "- **QIF-N.IJ** — Neural Injection (deliver signals into the brain)\n" +
        "- **QIF-D.HV** — Data Harvesting (intercept/steal neural data)\n" +
        "- **QIF-P.DS** — Processing Disruption (disrupt neural processing)\n" +
        "- **QIF-A.MN** — Authentication Manipulation (bypass neural auth)\n" +
        "- **QIF-S.EX** — System Exploitation (compromise BCI software/hardware)\n\n" +
        'Try: `tara_lookup` with `search_by: "tactic"` and `query: "QIF-N.IJ"`',
      next: "Step 3: Reading a Technique Entry",
    },
    {
      title: "Reading a Technique Entry",
      content:
        `Example: ${tara.techniques[0].id} — ${tara.techniques[0].name}\n\n` +
        `- **Status:** ${tara.techniques[0].status} — this attack has been demonstrated in research\n` +
        `- **Bands:** ${tara.techniques[0].bands} — spans from interface to lower neural bands\n` +
        `- **NISS:** ${tara.techniques[0].niss.score} (${tara.techniques[0].niss.severity}) — the biological impact score\n` +
        `- **Tactical severity:** ${tara.techniques[0].severity} — how bad if it succeeds\n` +
        `- **Dual-use:** ${tara.techniques[0].dual_use} — same mechanism used therapeutically as ${tara.techniques[0].therapeutic_analog}\n\n` +
        `Note: tactical severity and NISS severity may differ. A MITM attack is tactically critical but has low NISS (no direct biological impact).`,
    },
  ];

  const idx = Math.min(step - 1, steps.length - 1);
  return steps[idx];
}

function getNeuroethicsLesson(step: number): LessonStep {
  const guardrailData = getGuardrails();

  const steps: LessonStep[] = [
    {
      title: "Why Neuroethics Matters for BCI Security",
      content:
        "BCI security exists at the intersection of cybersecurity and neuroscience. " +
        "Without ethical constraints, security tools can become surveillance tools.\n\n" +
        "8 guardrails from published literature define the boundaries:\n" +
        guardrailData.guardrails
          .map((g) => `- **${g.id}: ${g.name}** (${g.source.author} ${g.source.year})`)
          .join("\n"),
      next: "Step 2: The Dual-Use Problem",
    },
    {
      title: "The Dual-Use Problem",
      content:
        "Every BCI threat technique has a therapeutic analog. Signal injection = neuromodulation. " +
        "Eavesdropping = diagnostic monitoring. Neural ransomware = responsive neurostimulation.\n\n" +
        "The boundary is consent, dosage, and oversight — not the mechanism.\n\n" +
        "G7 (Dual-Use Trap, Tennison & Moreno 2012): Security framing of neurotech risks enabling surveillance. " +
        "Every threat description must be paired with defensive controls. Offensive applications are out of scope.",
      next: "Step 3: What QIF Can and Cannot Claim",
    },
    {
      title: "What QIF Can and Cannot Claim",
      content:
        "QIF component bounds:\n\n" +
        guardrailData.componentBounds
          .map(
            (cb) =>
              `**${cb.component}** (${cb.fullName})\n` +
              `  Does: ${cb.does}\n` +
              `  Does NOT: ${cb.doesNot.join("; ")}\n` +
              `  Status: ${cb.status}`
          )
          .join("\n\n"),
    },
  ];

  const idx = Math.min(step - 1, steps.length - 1);
  return steps[idx];
}

function getNissLesson(step: number): LessonStep {
  const steps: LessonStep[] = [
    {
      title: "NISS: Why CVSS Isn't Enough",
      content:
        "CVSS scores IT vulnerabilities on exploitability and impact. " +
        "BCI threats need additional dimensions that CVSS doesn't cover:\n\n" +
        "1. **Biological Impact** — does it affect neural tissue?\n" +
        "2. **Coupling Risk** — how tightly coupled is the device to the brain?\n" +
        "3. **Coherence Disruption** — does it disrupt signal coherence?\n" +
        "4. **Consent Violation** — was the subject aware/consenting?\n" +
        "5. **Reversibility** — can the effect be undone?\n" +
        "6. **Neuroplasticity Risk** — can it cause lasting neural changes?\n\n" +
        "NISS scores these 6 dimensions into a single vector.",
    },
  ];

  const idx = Math.min(step - 1, steps.length - 1);
  return steps[idx];
}

const TOPIC_MAP: Record<string, (step: number) => LessonStep> = {
  quickstart: getQuickstart,
  tara: getTaraLesson,
  neuroethics: getNeuroethicsLesson,
  niss: getNissLesson,
  ttp: getTaraLesson, // alias
  clinical: getQuickstart, // simplified for now
};

export function bciLearn(input: BciLearnInput): ToolResult {
  const lessonFn = TOPIC_MAP[input.topic];
  if (!lessonFn) {
    return {
      content: [
        {
          type: "text",
          text: `Available topics: ${Object.keys(TOPIC_MAP).join(", ")}`,
        },
      ],
      isError: true,
    };
  }

  const step = input.step ?? 1;
  const lesson = lessonFn(step);

  let report = `## BCI Learn: ${lesson.title}\n\n${lesson.content}\n`;
  if (lesson.next) {
    report += `\n**Next:** ${lesson.next} (use step: ${step + 1})`;
  }

  return {
    content: [{ type: "text", text: sanitizeReport(report + DISCLAIMER) }],
  };
}
