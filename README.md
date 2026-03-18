# BCI Security

BCI security toolkit for researchers, developers, and engineers. Threat modeling, vulnerability scoring, pattern detection, and neuroethics compliance for brain-computer interfaces.

To our knowledge, no other tool provides structured neurosecurity analysis — threat taxonomies, neural impact scoring, or neuroethics compliance checking — inside an AI coding platform. As of March 2026, we are unaware of any equivalent in any AI coding platform marketplace.

## Requirements

No external dependencies. No API keys. No server to run.

**Status:** Research tool. Proposed framework, not an adopted standard. Not independently peer-reviewed.

## Installation

### From GitHub (recommended)
```bash
# Clone the repo
git clone https://github.com/qinnovates/bci-security.git

# Install as a local Claude Code plugin
claude plugins install --scope user ./bci-security
```

### From the Claude Code Marketplace (coming soon)
```bash
claude plugins install bci-security@qinnovates
```

### Verify installation
```bash
claude plugins list
# Should show: bci-security (enabled)
```

Then start a new Claude Code session and run `/bci-scan --demo`.

## Usage

### First run — see a threat report in 30 seconds
```
/bci-scan --demo
```
Scans a bundled OpenBCI Cyton EEG config. Shows applicable threats with severity scores and plain-English explanations. No setup required.

### Scan your own BCI project
```
/bci-scan .
```
Scans the current directory for BCI library imports (pylsl, brainflow, mne, pyedflib, OpenBCI), neural data files (.edf, .bdf, .xdf), and unsafe patterns (unencrypted streams, PII in data files, hardcoded API keys).

### Look up a specific technique
```
/bci explain QIF-T0001
```
Returns a three-layer explanation: one-line summary, plain-English description with therapeutic analog, and (on request) full technique card with sources and defensive controls.

### Generate a threat model for your device
```
/bci learn tara
```
Interactive walkthrough that teaches TARA, NISS, and neuroethics concepts by example. Then use the threat model generator:
```
/bci threat-model
```
Asks about your device class, signal types, connectivity, and deployment context. Produces a structured Markdown threat model document you can use for security reviews or regulatory submissions.

### Check text for neuroethics compliance
Paste any BCI-related text (paper draft, blog post, marketing copy) and the neuromodesty checker will scan for overclaims against 8 published guardrails from the neuroethics literature.

### Generate a shareable report
```
/bci report
```
Produces a clean Markdown threat assessment you can share with colleagues, paste in Slack, or attach to a security review.

## What It Does

- **Scans BCI code** for unsafe patterns (unencrypted neural streams, PII in data files, hardcoded credentials)
- **Detects PII in neural data pipelines** using 18 pattern-matching rules mapped to GDPR, CCPA, Chile Neurorights, UNESCO, and Mind Act
- **Generates compliance reports** assessing regulatory risk across 9 compliance domains with remediation roadmaps
- **Looks up threat techniques** from a catalog of 135 attacks targeting neural systems
- **Scores severity** using NISS, a neural-specific supplement to CVSS
- **Generates threat models** for BCI devices (consumer EEG, research systems, clinical implants)
- **Checks neuroethics compliance** against 8 published guardrails
- **Enforces Security Hardrails** — combined guardrails (ethical constraints) + hardening (technical enforcement) across all plugin output

## Quick Start

```
/bci-scan --demo
```

That's it. Scans a sample EEG device config and shows you what an attacker could exploit. Takes 30 seconds.

## Commands

| Command | What It Does |
|---------|-------------|
| `/bci-scan --demo` | Scan a sample device — start here |
| `/bci-scan <file>` | Scan your BCI code or config |
| `/bci compliance --demo` | Run a sample regulatory compliance report |
| `/bci compliance scan .` | Scan your project for PII and regulatory compliance |
| `/bci compliance assess` | Interactive compliance questionnaire |
| `/bci explain <ID>` | Explain a threat technique in plain English |
| `/bci report` | Generate a shareable threat assessment |
| `/bci learn <topic>` | Interactive walkthrough (tara, niss, neuroethics, quickstart) |
| `/bci glossary [term]` | Quick BCI security definitions |

## Security Hardrails

**Hardrails = Guardrails + Hardening.** This plugin enforces both ethical constraints and technical enforcement in a single defense-in-depth model.

**Guardrails** (what the system should NOT claim or do):
- 8 neuroethics guardrails from published literature (Morse, Poldrack, Racine, Ienca, Kellmeyer, Wexler, Tennison, Vul/Eklund)
- Regulatory compliance requirements mapped to GDPR, CCPA, Chile Neurorights, UNESCO, Mind Act
- Status qualifiers enforced on all QIF component references
- Dual-use framing — every threat paired with defensive controls

**Hardening** (technical enforcement):
- 18 PII detection patterns with regex matching across 6 categories (direct identifiers, neural identifiers, quasi-identifiers, health data, consent gaps, retention violations)
- 7-rule report sanitization engine (paths, credentials, hostnames, names, orgs, neural data, environment)
- Prompt injection defense (untrusted input rule across all skills)
- Neural data consent gate before scanning .edf/.bdf/.xdf files
- Zero-tolerance credential redaction (no opt-out)
- PostToolUse hook for neural data file detection

Every scan, report, and assessment passes through both layers before output reaches the user.

## The Core Insight

104 out of 135 cataloged attack techniques share mechanisms with therapeutic treatments. tDCS for depression uses the same current delivery as signal injection. Neurofeedback training uses the same reward pathways as cognitive manipulation.

The difference between therapy and attack is consent, dosage, and oversight.

## What's Inside

- **TARA**: 135 threat techniques across 11 biological domains, each with evidence tiers (CONFIRMED / EMERGING / DEMONSTRATED / THEORETICAL / PLAUSIBLE / SPECULATIVE)
- **NISS**: 6-dimensional severity scoring — Biological Impact, Coupling Risk, Coherence Disruption, Consent Violation, Reversibility, Neuroplasticity
- **3 Code Scanning Rules**: Transport encryption, data storage PII, API credential handling
- **18 PII Detection Patterns**: Regex-based detection for emails, phone numbers, national IDs, neural biometrics, cognitive state classifiers, clinical diagnoses, consent gaps, and retention violations
- **Compliance Report Engine**: Regulatory risk assessment across 9 domains, mapped to GDPR, CCPA, Chile Neurorights Law, UNESCO Recommendation, and Mind Act
- **Security Hardrails Framework**: Combined guardrails (ethical constraints) + hardening (technical enforcement) model
- **8 Neuroethics Guardrails**: From Morse, Poldrack, Racine, Ienca, Kellmeyer, Wexler, Tennison, Vul/Eklund
- **3 Sample Configs**: Consumer EEG, research system, clinical implant
- **Legal Disclaimers**: Comprehensive LEGAL.md covering liability limitations, data handling, privacy, and regulatory framework status

## Example Use Cases

**Running a regulatory compliance check before launch:**
> Run `/bci compliance scan .` on your BCI codebase. Get a structured report showing PII in neural data pipelines, missing consent sidecars, unencrypted data transfers, and cognitive state classification without consent gates. Each finding maps to specific GDPR articles, CCPA sections, and Chile Neurorights provisions. Export the remediation roadmap for your legal and engineering teams.

**Neurotech startup shipping a consumer EEG headband:**
> Run `/bci-scan .` on your BrainFlow + BLE codebase. Get flagged for unencrypted Bluetooth streams and PII in EDF headers. Generate a threat model filtered to your device class. Export for your FDA premarket cybersecurity submission.

**Medical device security team assessing an implanted BCI:**
> Run `/bci explain QIF-T0001` to understand signal injection at the electrode-tissue interface. Use the threat modeler to map all 135 techniques against your device profile. Score each with NISS to prioritize remediation.

**Researcher writing a BCI security paper:**
> Use `/bci learn tara` to understand the threat taxonomy. Look up techniques by domain, severity, or evidence tier. Run the neuromodesty checker on your draft to catch overclaims before peer review.

**Security engineer new to neurotechnology:**
> Start with `/bci-scan --demo` to see a threat report in 30 seconds. Run `/bci learn quickstart` for a 5-minute overview. Use the glossary for unfamiliar terms. You already know CVSS and ATT&CK — NISS and TARA are the BCI equivalents.

**Student exploring neurosecurity as a career:**
> Install the plugin, run the demo, walk through the learning modules. The 135-technique catalog with evidence tiers and therapeutic analogs is a structured introduction to a field that barely exists yet. Get in early.

**Pair programming with Claude Code or Coworker:**
> Working on a BCI project with Claude? The plugin activates automatically when it detects BCI library imports (pylsl, brainflow, mne, pyedflib). Claude flags unsafe patterns as you code — unencrypted LSL streams, PII in neural data headers, hardcoded device credentials — without you asking. Security guidance embedded in your workflow.

**Code review on a BCI pull request:**
> Point Claude at a PR touching BCI code. The plugin's passive scanner catches transport security gaps, data storage issues, and missing consent metadata. Generate a `/bci report` to attach to the review with specific TARA technique references and NISS severity scores.

**Regulatory prep for FDA submission:**
> Use `/bci threat-model` to generate a structured threat assessment mapped to your device class. The output references IEC 14971 and FDA premarket cybersecurity guidance. Hand the Markdown to your regulatory consultant — they fill in the gaps, you save hours of threat enumeration.

**Teaching a neurosecurity course:**
> Assign `/bci learn tara` and `/bci learn niss` as interactive homework. Students explore 135 real threat techniques with evidence tiers, therapeutic analogs, and severity scores. Better than reading a paper — they query, filter, and reason about threats hands-on.

## Platform Compatibility

Built for **Claude Code** and **Claude Coworker**. The plugin uses standard Claude Code plugin architecture (skills, commands, hooks) and works anywhere Claude Code runs.

**Coming soon:** Codex marketplace submission for OpenAI Codex CLI compatibility. The plugin's architecture is agent-agnostic — skills are markdown, data is JSON, hooks are lightweight scripts. Portable to any AI coding platform that supports plugin systems.

## Who This Is For

- **Neurotech startups** building BCI products
- **Medical device security teams** doing threat assessments
- **BCI researchers** who want structured security analysis
- **Students** entering the neurosecurity field

## Privacy, Data Handling & Legal

For comprehensive legal notices, privacy disclaimers, and limitation of liability, see **[LEGAL.md](LEGAL.md)**.

**Summary:**

- This plugin contains **no network calls** and **stores no data**. But the AI agent hosting it sends conversation context (including scanned files) to its host API.
- **Neural data is sensitive data** under GDPR (Art.9), CCPA (biometric), Chile Neurorights (organ tissue), and HIPAA (PHI when identifiable).
- **Do not scan files containing real patient data, IRB-restricted data, or proprietary protocols** unless your data governance policy permits sending them to your AI platform.
- **Report sanitization is best-effort** (AI-instruction-based, not deterministic). Always review reports before sharing externally.
- **This is not a medical device.** Output does not satisfy FDA, EU MDR, or IEC certification requirements.
- **This is not legal advice.** Compliance determinations require qualified legal counsel.
- **Validation is your responsibility.** All findings require independent professional verification.

### Regulatory Frameworks Referenced

| Framework | Status | Jurisdiction |
|-----------|--------|-------------|
| GDPR | Enacted (2018) | EU/EEA |
| CCPA/CPRA | Enacted (2020/2023) | California |
| Chile Neurorights Law | Enacted (2021/2024) | Chile |
| UNESCO Recommendation | Adopted/In development | International (non-binding) |
| MIND Act | Proposed | US (not enacted) |
| HIPAA | Enacted (1996) | US covered entities |

## Important Caveats

This plugin is built on the QIF framework, which is:
- **Proposed** — not adopted by any standards body
- **Unvalidated** — not independently peer-reviewed or replicated
- **In development** — not production-ready for clinical use

NISS supplements CVSS. It does not replace it. TARA supplements MITRE ATT&CK for a domain ATT&CK does not cover. Neither is a standard.

Every clinical impact statement in this plugin includes "for threat modeling purposes" — these are threat modeling categories, not clinical predictions.

## Licenses

- **Code and skill definitions:** Apache 2.0 (`LICENSE-CODE`) — covers all `.md` files in `commands/`, `skills/`, and `agents/`, plus any scripts
- **Data** (TARA catalog, NISS scores, guardrails, sample configs): CC BY 4.0 (`LICENSE-DATA`) — covers all `.json` files in `data/`

Use the data in commercial products, research, or derivative works. Just give credit.

## Contributing

Contributions welcome. To propose a new TARA technique, open a GitHub issue using the Technique Proposal template.

## Structure

```
bci-security/
├── .claude-plugin/plugin.json     Plugin metadata
├── commands/
│   ├── bci.md                     Entry point (/bci)
│   └── bci-scan.md                Code scanner (/bci-scan --demo)
├── skills/
│   ├── tara-lookup/               Query 135 threat techniques
│   ├── niss-score/                Neural impact severity scoring
│   ├── neuromodesty-check/        8 guardrail compliance checks
│   ├── bci-threat-model/          Guided threat model generation
│   ├── bci-scan/                  Passive code scanning
│   ├── bci-compliance/            Regulatory compliance reports
│   └── bci-learn/                 Interactive tutorials
├── agents/
│   └── threat-modeler.md          Multi-step threat modeling agent
├── hooks/
│   ├── hooks.json                 Hook configuration
│   └── neural-data-guard.py       Neural data file detection script
├── data/
│   ├── tara-techniques.json       135 techniques (~120 KB)
│   ├── niss-device-scores.json    22 device scores
│   ├── security-controls.json     Controls by hourglass band
│   ├── guardrails.json            8 neuroethics guardrails
│   ├── pii-patterns.json          18 PII detection patterns
│   ├── regulatory-compliance.json 9 compliance domains, 5 frameworks
│   ├── hardrails.json             Security hardrails framework
│   └── samples/                   3 demo device configs
├── LEGAL.md                       Legal notices & privacy disclaimer
├── LICENSE-CODE                   Apache 2.0
└── LICENSE-DATA                   CC BY 4.0
```

## Built By

[QInnovate](https://qinnovate.com) — Open neurosecurity research.
