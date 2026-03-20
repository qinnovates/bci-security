# BCI Security

> **Moved to [bci-security/plugin](https://github.com/bci-security/plugin).** This repo ([qinnovates/bci-security](https://github.com/qinnovates/bci-security)) is the original archive with full version history.

BCI security toolkit for researchers, developers, and engineers. Threat modeling, vulnerability scoring, pattern detection, and neuroethics compliance for brain-computer interfaces.

To our knowledge, no other tool provides structured neurosecurity analysis — threat taxonomies, neural impact scoring, or neuroethics compliance checking — inside an AI coding platform. As of March 2026, we are unaware of any equivalent in any AI coding platform marketplace.

## Quick Start

```
/bci-scan --demo
```

Scans a sample BCI device config with intentional security violations. Shows a threat report with TARA technique mappings and NISS severity scores in 30 seconds. No setup required beyond installation.

## Requirements

No external dependencies. No API keys. No server to run. **No network calls.** The plugin processes everything locally — it never phones home, never sends data to external endpoints.

**Status:** Research tool. Proposed framework, not an adopted standard. Not independently peer-reviewed.

## Installation

### Claude Code
```bash
# Add the BCI Security marketplace
claude plugins marketplace add https://github.com/bci-security/plugin.git

# Install the plugin
claude plugins install bci-security

# Verify
claude plugins list
# Should show: bci-security@bci-security ✔ enabled

# IMPORTANT: Restart Claude Code to load the plugin
# Start a new session, then run /bci-scan --demo
```

> **You must restart Claude Code after installing.** The plugin's skills and commands load at session start. They won't be available in the session where you ran the install. Start a new session, then run `/bci-scan --demo`.

**To update:**
```bash
claude plugins update bci-security
# Then restart Claude Code
```

### MCP Server (Any MCP Client)

Works with Cursor, Windsurf, VS Code, and any MCP-compatible client.

```bash
# Clone the repo
git clone https://github.com/bci-security/plugin.git
cd plugin/mcp-server

# Install and build
npm install
npm run build

# Add to your MCP client config (e.g., claude_desktop_config.json):
```

```json
{
  "mcpServers": {
    "bci-security": {
      "command": "node",
      "args": ["/path/to/plugin/mcp-server/dist/index.js"]
    }
  }
}
```

**8 tools:** `tara_lookup`, `niss_score`, `bci_scan`, `bci_compliance`, `bci_threat_model`, `bci_anonymize`, `neuromodesty_check`, `bci_learn`

**7 resources:** TARA techniques, PII patterns, NISS device scores, regulatory compliance, neuroethics guardrails, security controls, hardrails framework

**Security:** No file system access beyond bundled data. No network calls. No shell execution. All inputs validated with Zod. All outputs sanitized (credentials redacted, paths stripped). Prompt injection detection on all user-supplied strings.

### Other AI Coding Platforms
The plugin is pure markdown and JSON. No compiled code, no runtime dependencies. Clone the repo and adapt the `skills/` directory to your platform's skill format:

```bash
git clone https://github.com/bci-security/plugin.git
```

Each `skills/*/SKILL.md` file is a self-contained instruction set. Copy it into your platform's skill directory, or paste it directly into your AI conversation along with the relevant `data/*.json` file.

### Manual Use (Any AI)
Copy the contents of any SKILL.md file and the relevant data JSON into your AI conversation. The instructions work with any model that can read files and follow structured prompts.


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

### Learn the framework
```
/bci learn quickstart    # 5-minute overview
/bci learn ttp           # TARA ↔ MITRE ATT&CK mapping (security professionals)
/bci learn clinical      # Therapy-attack boundary (clinicians + researchers)
/bci learn tara          # Full threat catalog walkthrough
/bci learn niss          # Severity scoring deep dive
/bci learn neuroethics   # The 8 guardrails
```
Interactive walkthroughs that teach by doing with real data from the technique catalog. Then use the threat model generator:
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

## Understanding QIF and TARA

This section is for security professionals, clinicians, and researchers who want to understand how the framework works — not just run scans.

### How to Read a TARA Technique

Every technique in the catalog follows this structure:

```
ID:                 QIF-T0001
Name:               Signal injection
Tactic:             QIF-N.IJ (Neural Injection)
Bands:              I0–N1 (interface layer to first neural layer)
Status:             CONFIRMED
Severity:           high
NISS Vector:        NISS:1.1/BI:H/CR:H/CD:H/CV:E/RV:P/NP:T
NISS Score:         6.1/10
Mechanism:          Electrical current delivery at electrode-tissue interface
Therapeutic Analog: tDCS/tACS neuromodulation
Dual Use:           confirmed
Sources:            Kohno et al. 2009, Bonaci et al. 2015
```

**For security professionals:** `tactic` maps to your kill chain, `bands` maps to the stack layer, `status` tells you how real the threat is, `mitigations` tells you what to do about it.

**For clinicians:** `therapeutic_analog` shows which treatment uses this mechanism, `dual_use` shows how certain the overlap is, `niss` captures biological severity across 6 dimensions that CVSS cannot express.

Run `/bci explain QIF-T0001` to see any technique card interactively.

### How TARA Relates to MITRE ATT&CK

If you know MITRE ATT&CK, you already know the model:

| Concept | ATT&CK | TARA |
|---------|--------|------|
| **Tactics** | What the attacker wants | Same — 16 neural-specific tactics |
| **Techniques** | How they do it | Same — 135 techniques targeting neural systems |
| **Procedures** | Specific implementation steps | Device-specific — left to your threat model |

TARA fills the gap ATT&CK was never designed for. ATT&CK covers the silicon side (firmware, Bluetooth, cloud API). TARA covers what happens after the attacker reaches the neural interface — signal injection, cognitive manipulation, biological evasion, neural data harvesting.

Several TARA tactics have **no ATT&CK equivalent**: Cognitive Exploitation (QIF-C.EX), Cognitive Impairment (QIF-C.IM), Biological Integration (QIF-B.IN), Biological Evasion (QIF-B.EV). These represent the domain gap that motivated building TARA.

In practice, a BCI threat model uses both: ATT&CK for IT infrastructure, TARA for neural-specific techniques. They're complementary.

Run `/bci learn ttp` for a full interactive walkthrough with examples.

### The Therapy-Attack Boundary

104 out of 135 techniques share physical mechanisms with therapeutic treatments. This is the defining characteristic of BCI security.

| Treatment | Attack Technique | Same Mechanism | Boundary |
|-----------|-----------------|----------------|----------|
| tDCS for depression | QIF-T0001 Signal injection | Electrical current at electrode-tissue interface | Consent + current density limits |
| DBS for Parkinson's | QIF-T0002 Neural ransomware | Closed-loop stimulation parameter control | Clinical oversight + parameter bounds |
| EEG diagnostics | QIF-T0003 Eavesdropping | Passive neural signal capture | Data access controls + consent |
| rTMS for stroke rehab | QIF-T0009 rTMS exploitation | Magnetic pulse delivery to cortex | Frequency/intensity bounds |

The mechanism is the same. The boundary between therapy and attack is **consent** (did the person agree?), **dosage** (within safe parameters?), and **oversight** (is a qualified professional involved?).

If you're a clinician, your treatment protocols already define the safe parameter space. If you're a security engineer, the therapeutic parameters tell you what "normal" looks like — your detection logic is the delta between therapeutic and anomalous behavior.

Run `/bci learn clinical` for the full walkthrough with clinical depth and evidence tiers.

### Learning Paths

| Path | Audience | Time | Command |
|------|----------|------|---------|
| Quickstart | Anyone | 5 min | `/bci learn quickstart` |
| TARA | Security + research | 15 min | `/bci learn tara` |
| TTPs | Security professionals | 10 min | `/bci learn ttp` |
| Clinical | Clinicians + researchers | 15 min | `/bci learn clinical` |
| NISS | Security + clinical | 10 min | `/bci learn niss` |
| Neuroethics | Everyone | 10 min | `/bci learn neuroethics` |

All learning paths are interactive — Claude walks you through concepts with real data from the technique catalog, not hypothetical examples. Ask questions as you go.

## Design Philosophy

This plugin is designed for **reviewing anonymized BCI data with AI coding agents**. It performs clinical and threat mapping based on patterns that research labs derive from their own data. The plugin does not process raw patient data, run on live devices, or replace clinical judgment.

**Qinnovate provides pre-tagged samples from open research datasets** (Mendeley, PhysioNet, IEEE DataPort) so you can test the scanner, compliance checker, and threat modeler without needing your own BCI data. These samples come tagged with DSM-5 codes and TARA technique mappings for educational use.

**The plugin is modular.** Each skill operates independently. Use the scanner alone, the compliance checker alone, or chain them together. Add new detection rules, PII patterns, or regulatory frameworks without touching existing skills. The data layer (JSON) is separate from the logic layer (SKILL.md), so you can update threat techniques or compliance requirements independently.

## What It Does

- **Scans BCI code** for unsafe patterns (unencrypted neural streams, PII in data files, hardcoded credentials)
- **Detects PII in neural data pipelines** using 18 pattern-matching rules mapped to GDPR, CCPA, Chile Neurorights, UNESCO, and Mind Act
- **Generates compliance reports** assessing regulatory risk across 9 compliance domains with remediation roadmaps
- **Looks up threat techniques** from a catalog of 135 attacks targeting neural systems
- **Scores severity** using NISS, a neural-specific supplement to CVSS
- **Generates threat models** for BCI devices (consumer EEG, research systems, clinical implants)
- **Checks neuroethics compliance** against 8 published guardrails
- **Anonymizes neural data before processing** — scans EDF/BDF/XDF/FIF/NWB/GDF files for PII in headers, filenames, and metadata, then generates remediation scripts
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
| `/bci anonymize .` | Scan neural data files for PII before processing |
| `/bci anonymize --demo` | Demo anonymization on sample ADHD data |
| `/bci compliance --demo` | Run a sample regulatory compliance report |
| `/bci compliance scan .` | Scan your project for PII and regulatory compliance |
| `/bci compliance assess` | Interactive compliance questionnaire |
| `/bci explain <ID>` | Explain a threat technique in plain English |
| `/bci report` | Generate a shareable threat assessment |
| `/bci learn <topic>` | Interactive walkthrough (tara, niss, neuroethics, quickstart, ttp, clinical) |
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
- **7 Code Scanning Rules**: Transport encryption, data storage PII, API credential handling, PII in neural data pipelines, ML model security, stimulation safety bounds, MNE/NWB pipeline security
- **18 PII Detection Patterns**: Regex-based detection for emails, phone numbers, national IDs, neural biometrics, cognitive state classifiers, clinical diagnoses, consent gaps, and retention violations
- **Compliance Report Engine**: Regulatory risk assessment across 9 domains, mapped to GDPR, CCPA, Chile Neurorights Law, UNESCO Recommendation, and Mind Act
- **Security Hardrails Framework**: Combined guardrails (ethical constraints) + hardening (technical enforcement) model
- **8 Neuroethics Guardrails**: From Morse, Poldrack, Racine, Ienca, Kellmeyer, Wexler, Tennison, Vul/Eklund
- **5 Sample Files**: 3 device configs (consumer EEG, research system, clinical implant), 1 ADHD research study config (with intentional compliance violations), 1 vulnerable BCI Python script (with security anti-patterns)
- **6 Interactive Learning Paths**: quickstart, tara, ttp, clinical, niss, neuroethics — teach by doing with real catalog data
- **Legal Disclaimers**: Comprehensive LEGAL.md covering liability limitations, data handling, privacy, and regulatory framework status

## Example Use Cases

**Running a regulatory compliance check before launch:**
> Run `/bci compliance scan .` on your BCI codebase. Get a structured report showing PII in neural data pipelines, missing consent sidecars, unencrypted data transfers, and cognitive state classification without consent gates. Each finding maps to specific GDPR articles, CCPA sections, and Chile Neurorights provisions. Export the remediation roadmap for your legal and engineering teams.

**Neurotech startup shipping a consumer EEG headband:**
> Run `/bci-scan .` on your BrainFlow + BLE codebase. Get flagged for unencrypted Bluetooth streams and PII in EDF headers. Generate a threat model filtered to your device class. Export for your FDA premarket cybersecurity submission.

**Medical device security team assessing an implanted BCI:**
> Run `/bci explain QIF-T0001` to understand signal injection at the electrode-tissue interface. Use `/bci learn clinical` to see how every technique maps to its therapeutic equivalent — your clinical protocols define the safe parameter space, and security enforces the boundary. Use the threat modeler to map all 135 techniques against your device profile. Score each with NISS to prioritize remediation.

**Researcher writing a BCI security paper:**
> Use `/bci learn tara` to understand the threat taxonomy. Run `/bci learn clinical` to explore the therapy-attack boundary with evidence tiers. Look up techniques by domain, severity, or evidence tier. Run the neuromodesty checker on your draft to catch overclaims before peer review.

**Security engineer new to neurotechnology:**
> Start with `/bci-scan --demo` to see a threat report in 30 seconds. Run `/bci learn quickstart` for a 5-minute overview, then `/bci learn ttp` to map TARA to the MITRE ATT&CK model you already know. NISS is to CVSS what TARA is to ATT&CK — the neural extension.

**Clinician reviewing BCI device security:**
> Run `/bci learn clinical` — it speaks your language. Every technique maps to a treatment you already know: tDCS, DBS, neurofeedback, rTMS. The 6 NISS dimensions (biological impact, coupling risk, neuroplasticity) map to clinical parameters you already monitor. Your expertise in safe dosage boundaries IS security expertise. The plugin helps you formalize what you already know into a threat model.

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

## Known Limitations

This plugin uses AI instruction-based enforcement, not runtime-enforced constraints. See `docs/SAFETY.md` Section 12 for details.

- **Injection defense is best-effort.** Keyword blocklists can be bypassed via encoding, homoglyphs, or semantic paraphrase. Defense-in-depth (multiple layers) is the strategy.
- **PII detection uses pattern matching.** False positives and false negatives are expected. PII-011 (cognitive state classification) requires BCI context keywords to reduce false positives from non-neural uses.
- **Report sanitization is AI-instruction-based, not deterministic.** The same AI model generates and verifies the report. Always review output before sharing externally.
- **NISS severity vs editorial severity may differ.** A technique can be tactically critical but have low biological impact (e.g., man-in-the-middle: critical tactic, NISS 2.7/10). Both are shown when relevant.

### NISS Vector Quick Reference

```
NISS:1.1/BI:H/CR:H/CD:H/CV:E/RV:P/NP:T
      │    │    │    │    │    └ Neuroplasticity (N/T/P/C)
      │    │    │    │    └─── Reversibility (F/R/P/I)
      │    │    │    └──────── Consent Violation (N/I/E/F)
      │    │    └───────────── Coherence Disruption (N/L/M/H/C)
      │    └────────────────── Coupling Risk (N/L/M/H)
      └─────────────────────── Biological Impact (N/L/M/H/C)
```

## Licenses

- **Code and skill definitions:** Apache 2.0 (`LICENSE-CODE`) — covers all `.md` files in `commands/`, `skills/`, and `agents/`, plus any scripts
- **Data** (TARA catalog, NISS scores, guardrails, sample configs): CC BY 4.0 (`LICENSE-DATA`) — covers all `.json` files in `data/`

Use the data in commercial products, research, or derivative works. Just give credit.

## Contributing

Contributions welcome. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for schemas and guides on adding TARA techniques, PII patterns, compliance frameworks, and security controls.

## Structure

```
bci-security/
├── .claude-plugin/plugin.json     Plugin metadata
├── CONTRIBUTING.md                Contributing guide with data schemas
├── commands/                      Thin routers — route user input to skills
│   ├── bci.md                     Entry point (/bci) — routes subcommands
│   └── bci-scan.md                Code scanner (/bci-scan --demo)
├── skills/
│   ├── tara-lookup/               Query 135 threat techniques
│   ├── niss-score/                Neural impact severity scoring
│   ├── neuromodesty-check/        8 guardrail compliance checks
│   ├── bci-threat-model/          Guided threat model generation
│   ├── bci-scan/                  Passive code scanning
│   ├── bci-anonymize/             Pre-processing PII anonymizer
│   ├── bci-compliance/            Regulatory compliance reports
│   └── bci-learn/                 Interactive tutorials
├── agents/
│   └── threat-modeler.md          Multi-step threat modeling agent
├── hooks/
│   ├── hooks.json                 Hook configuration (PostToolUse on Write|Edit)
│   └── neural-data-guard.py       Passive guardrail: alerts when neural data files are written
├── data/
│   ├── tara-techniques.json       135 techniques (~120 KB)
│   ├── niss-device-scores.json    22 device scores
│   ├── security-controls.json     Controls by hourglass band
│   ├── guardrails.json            8 neuroethics guardrails
│   ├── pii-patterns.json          18 PII detection patterns
│   ├── regulatory-compliance.json 9 compliance domains, 5 frameworks
│   ├── hardrails.json             Security hardrails framework (design reference, not loaded at runtime)
│   └── samples/                   5 demo files (3 device configs + study + vuln script)
├── mcp-server/                    MCP server (any MCP client)
│   ├── src/
│   │   ├── index.ts               Server entry point (stdio transport)
│   │   ├── tools/                 8 tool implementations
│   │   ├── resources/             7 resource definitions
│   │   ├── security/              Injection, credential, sanitizer, path-guard, validator
│   │   ├── data/                  Typed JSON loader with validation
│   │   └── types/                 TypeScript type definitions
│   ├── package.json
│   └── tsconfig.json
├── docs/
│   ├── SAFETY.md                  Canonical security specification
│   ├── ARCHITECTURE.md            Component map & data flow
│   └── INTEGRATION.md             Device integration guide (OpenBCI, BrainFlow, MNE, NWB, Emotiv, LSL)
├── LEGAL.md                       Legal notices & privacy disclaimer
├── LICENSE-CODE                   Apache 2.0
└── LICENSE-DATA                   CC BY 4.0
```

## Version History

Full version history is available at the [original archive repo](https://github.com/qinnovates/bci-security).

## Built By

[QInnovate](https://qinnovate.com) — Open neurosecurity research.
