# BCI Security Plugin — Architecture Reference

## Overview

BCI Security is a multi-skill plugin providing threat modeling, vulnerability scoring, PII detection, regulatory compliance reporting, and neuroethics compliance checking for brain-computer interface systems.

**Architecture pattern:** Multi-skill plugin with shared data layer and centralized security specification.

## Component Map

```
┌─────────────────────────────────────────────────────────┐
│  User Interface Layer                                    │
│  ┌──────────┐ ┌──────────┐                              │
│  │ /bci     │ │ /bci-scan│  ← Commands (entry points)   │
│  └────┬─────┘ └────┬─────┘                              │
│       │             │                                    │
├───────┼─────────────┼────────────────────────────────────┤
│  Skill Layer        │                                    │
│  ┌─────────┐ ┌──────┴────┐ ┌───────────┐ ┌───────────┐ │
│  │tara-    │ │bci-scan   │ │bci-       │ │bci-threat-│ │
│  │lookup   │ │(passive)  │ │compliance │ │model      │ │
│  ├─────────┤ ├───────────┤ ├───────────┤ ├───────────┤ │
│  │niss-    │ │neuro-     │ │bci-learn  │ │           │ │
│  │score    │ │modesty    │ │           │ │           │ │
│  └────┬────┘ └─────┬─────┘ └─────┬─────┘ └─────┬─────┘ │
│       │            │             │              │        │
├───────┼────────────┼─────────────┼──────────────┼────────┤
│  Agent Layer       │             │              │        │
│       │     ┌──────┴──────┐      │              │        │
│       │     │threat-      │      │              │        │
│       │     │modeler      │      │              │        │
│       │     └──────┬──────┘      │              │        │
│       │            │             │              │        │
├───────┼────────────┼─────────────┼──────────────┼────────┤
│  Security Layer (docs/SAFETY.md — canonical reference)   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │Injection │ │Credential│ │Report    │ │Consent     │ │
│  │Defense   │ │Detection │ │Sanitize  │ │Gate        │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                │
│  │Path      │ │Arguments │ │Self-     │                 │
│  │Restrict  │ │Validate  │ │Verify    │                 │
│  └──────────┘ └──────────┘ └──────────┘                 │
│                                                          │
├──────────────────────────────────────────────────────────┤
│  Data Layer (loaded on demand, not at startup)           │
│  ┌───────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │tara-techniques│ │pii-patterns  │ │guardrails      │ │
│  │(135 techniques)│ │(18 patterns) │ │(8 guardrails)  │ │
│  ├───────────────┤ ├──────────────┤ ├────────────────┤ │
│  │niss-device-   │ │regulatory-   │ │security-       │ │
│  │scores (22)    │ │compliance (9)│ │controls        │ │
│  ├───────────────┤ ├──────────────┤ ├────────────────┤ │
│  │hardrails      │ │samples/ (3)  │ │                │ │
│  └───────────────┘ └──────────────┘ └────────────────┘ │
│                                                          │
├──────────────────────────────────────────────────────────┤
│  Hook Layer (passive enforcement)                        │
│  ┌──────────────────────────────────┐                   │
│  │neural-data-guard.py              │                   │
│  │PostToolUse on Write|Edit         │                   │
│  │Detects neural data file writes   │                   │
│  └──────────────────────────────────┘                   │
└──────────────────────────────────────────────────────────┘
```

## Data Flow

```
User request
    │
    ▼
Command layer (bci.md / bci-scan.md)
    │ Arguments validated (Section 7 of SAFETY.md)
    │ Injection patterns checked (Section 2 of SAFETY.md)
    │
    ▼
Skill layer (SKILL.md loaded on demand)
    │ Reads data files from data/
    │ Data file content treated as untrusted for injection
    │ Scans user files (if scan mode)
    │ User file content treated as untrusted
    │
    ▼
Security layer (SAFETY.md rules applied)
    │ Credential detection (10 regex patterns, Section 3)
    │ Report sanitization (7 rules, Section 4)
    │ Self-verification pass
    │
    ▼
Output to user
```

## Security Hardrails Model

**Hardrails = Guardrails + Hardening**

| Layer | Type | What | Enforcement |
|-------|------|------|-------------|
| GL-01 | Guardrail | 8 neuroethics constraints (G1-G8) | neuromodesty-check skill |
| GL-02 | Guardrail | Regulatory compliance (5 frameworks, 9 domains) | bci-compliance skill |
| GL-03 | Guardrail | Status qualifiers (proposed/unvalidated) | Mandatory disclaimers |
| GL-04 | Guardrail | Dual-use framing (defensive only) | G7 check + report format |
| HL-01 | Hardening | PII detection (18 patterns) | bci-compliance scan |
| HL-02 | Hardening | Report sanitization (7 rules) | All report surfaces |
| HL-03 | Hardening | Injection defense (17 trigger phrases) | All skills/commands/agents |
| HL-04 | Hardening | Neural data consent gate | bci-scan command + skill |
| HL-05 | Hardening | Credential detection (10 regex patterns) | Zero-tolerance redaction |
| HL-06 | Hardening | Neural data file hook | PostToolUse on Write/Edit |

## Token Efficiency

Progressive disclosure architecture per Anthropic recommendations:

1. **At startup:** Only skill metadata (name, description from frontmatter) loads
2. **When invoked:** Full SKILL.md loads (<500 lines each, largest: 219)
3. **On demand:** Data files load when skills read them
4. **Reference:** docs/SAFETY.md and docs/ARCHITECTURE.md load only when needed

## File Organization

```
bci-security/
├── .claude-plugin/plugin.json      Manifest (5 lines)
├── commands/                        Entry points
│   ├── bci.md                       Router (89 lines)
│   └── bci-scan.md                  Scanner (198 lines)
├── skills/                          Capabilities (7 skills)
│   ├── bci-scan/SKILL.md            Passive scanner (68 lines)
│   ├── bci-compliance/SKILL.md      Compliance reports (219 lines)
│   ├── bci-threat-model/SKILL.md    Threat modeling (183 lines)
│   ├── bci-learn/SKILL.md           Interactive learning (78 lines)
│   ├── neuromodesty-check/SKILL.md  Ethics compliance (94 lines)
│   ├── niss-score/SKILL.md          Severity scoring (89 lines)
│   └── tara-lookup/SKILL.md         Technique lookup (68 lines)
├── agents/
│   └── threat-modeler.md            Specialist agent (42 lines)
├── hooks/
│   ├── hooks.json                   Hook config
│   └── neural-data-guard.py         Neural data detection
├── data/                            Reference data (loaded on demand)
│   ├── tara-techniques.json         135 techniques
│   ├── niss-device-scores.json      22 device scores
│   ├── pii-patterns.json            18 PII detection patterns
│   ├── regulatory-compliance.json   9 compliance domains
│   ├── hardrails.json               Hardrails framework
│   ├── guardrails.json              8 neuroethics guardrails
│   ├── security-controls.json       QIF band controls
│   └── samples/                     3 demo configs
├── docs/                            Reference (loaded on demand)
│   ├── SAFETY.md                    Canonical security spec
│   └── ARCHITECTURE.md              This file
├── LEGAL.md                         Legal notices & disclaimers
├── README.md                        User-facing documentation
├── LICENSE-CODE                     Apache 2.0
└── LICENSE-DATA                     CC BY 4.0
```
