# BCI Security

BCI security toolkit for researchers, developers, and engineers. Threat modeling, vulnerability scoring, pattern detection, and neuroethics compliance for brain-computer interfaces.

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
- **Looks up threat techniques** from a catalog of 135 attacks targeting neural systems
- **Scores severity** using NISS, a neural-specific supplement to CVSS
- **Generates threat models** for BCI devices (consumer EEG, research systems, clinical implants)
- **Checks neuroethics compliance** against 8 published guardrails

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
| `/bci explain <ID>` | Explain a threat technique in plain English |
| `/bci report` | Generate a shareable threat assessment |
| `/bci learn <topic>` | Interactive walkthrough (tara, niss, neuroethics, quickstart) |
| `/bci glossary [term]` | Quick BCI security definitions |

## The Core Insight

104 out of 135 cataloged attack techniques share mechanisms with therapeutic treatments. tDCS for depression uses the same current delivery as signal injection. Neurofeedback training uses the same reward pathways as cognitive manipulation.

The difference between therapy and attack is consent, dosage, and oversight.

## What's Inside

- **TARA**: 135 threat techniques across 11 biological domains, each with evidence tiers (CONFIRMED / EMERGING / DEMONSTRATED / THEORETICAL / PLAUSIBLE / SPECULATIVE)
- **NISS**: 6-dimensional severity scoring — Biological Impact, Coupling Risk, Coherence Disruption, Consent Violation, Reversibility, Neuroplasticity
- **3 Code Scanning Rules**: Transport encryption, data storage PII, API credential handling
- **8 Neuroethics Guardrails**: From Morse, Poldrack, Racine, Ienca, Kellmeyer, Wexler, Tennison, Vul/Eklund
- **3 Sample Configs**: Consumer EEG, research system, clinical implant

## Who This Is For

- **Neurotech startups** building BCI products
- **Medical device security teams** doing threat assessments
- **BCI researchers** who want structured security analysis
- **Students** entering the neurosecurity field

## Important Caveats

This plugin is built on the QIF framework, which is:
- **Proposed** — not adopted by any standards body
- **Unvalidated** — not independently peer-reviewed or replicated
- **In development** — not production-ready for clinical use

NISS supplements CVSS. It does not replace it. TARA supplements MITRE ATT&CK for a domain ATT&CK does not cover. Neither is a standard.

Every clinical impact statement in this plugin includes "for threat modeling purposes" — these are threat modeling categories, not clinical predictions.

## Licenses

- **Code:** Apache 2.0 (`LICENSE-CODE`)
- **Data** (TARA catalog, NISS scores, guardrails): CC BY-SA 4.0 (`LICENSE-DATA`)

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
│   └── bci-learn/                 Interactive tutorials
├── agents/
│   └── threat-modeler.md          Multi-step threat modeling agent
├── hooks/hooks.json               Neural data file detection
├── data/
│   ├── tara-techniques.json       135 techniques (~120 KB)
│   ├── niss-device-scores.json    22 device scores
│   ├── security-controls.json     Controls by hourglass band
│   ├── guardrails.json            8 neuroethics guardrails
│   └── samples/                   3 demo device configs
├── LICENSE-CODE                   Apache 2.0
└── LICENSE-DATA                   CC BY-SA 4.0
```

## Built By

[QInnovate](https://qinnovate.com) — Open neurosecurity research.
