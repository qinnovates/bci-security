# Legal Notices, Privacy Disclaimer & Limitation of Liability

**BCI Security Tools v1.0** — QInnovate

**Effective Date:** 2026-03-17
**Last Updated:** 2026-03-17

---

## 1. Nature of This Tool

BCI Security Tools is a **research tool** that provides security analysis, threat modeling, and compliance assessment capabilities for brain-computer interface (BCI) systems. It is built on the QIF framework, which is:

- **Proposed** — not adopted by any standards body (IEEE, ISO, NIST, or otherwise)
- **Unvalidated** — not independently peer-reviewed or replicated by third parties
- **In development** — not production-ready for clinical, regulatory, or procurement decisions

This tool runs inside AI coding agents (Claude Code, Codex, etc.) that process information via their host AI platform's API. **The plugin itself contains no network calls, stores no data, and runs no server.** However, the AI agent hosting this plugin sends conversation context — including scanned file contents — to its host API for processing.

## 2. Not Legal Advice

**Nothing in this tool's output constitutes legal advice, a legal opinion, or a compliance determination.**

Regulatory references in this tool (GDPR, CCPA/CPRA, Chile Neurorights Law, UNESCO Recommendation on the Ethics of Neurotechnology, MIND Act) are simplified mappings for threat modeling and security assessment purposes. These mappings:

- May not capture all applicable requirements, exceptions, or interpretive nuances
- Do not account for jurisdiction-specific implementation, case law, or regulatory guidance
- Do not substitute for review by qualified legal counsel familiar with your specific circumstances
- May reference proposed or draft legislation (e.g., MIND Act) that has not been enacted

**If you need a compliance determination, consult a qualified attorney.**

## 3. Not a Medical Device

This tool is **not a medical device** under any jurisdiction's regulatory framework, including but not limited to:

- **United States:** Not a medical device under 21 CFR 820 or FDA guidance. Output does not satisfy FDA premarket cybersecurity submission requirements (per FDA guidance "Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions," 2023).
- **European Union:** Not a medical device under EU MDR 2017/745. Output does not satisfy EU MDR cybersecurity requirements or IEC 62304 software lifecycle documentation.
- **International:** Does not satisfy IEC 14971 risk management documentation requirements, IEC 62443 industrial cybersecurity certification, or any national medical device regulatory requirement.

**Do not use output from this tool as the sole basis for clinical decisions, patient safety determinations, or regulatory filings.**

## 4. Privacy & Data Handling

### 4.1 How Data Flows

```
Your files → AI Agent (reads files) → Host API (processes context) → AI Agent (generates report)
                                        ↑
                              Plugin instructions + data are LOCAL
                              AI processing is NOT local
```

When you run a scan (e.g., `/bci-scan .` or `/bci compliance scan .`), the AI agent reads your files and includes their contents in the context sent to the host AI platform's API. **You are responsible for ensuring this data flow complies with your data governance obligations.**

### 4.2 Neural Data is Sensitive Data

Under applicable regulatory frameworks:

| Framework | Neural Data Classification |
|-----------|--------------------------|
| **GDPR** (EU) | Special category data under Art.9(1) when linked to identifiable persons — biometric data for identification, health data |
| **CCPA/CPRA** (California) | Sensitive personal information under 1798.140(ae); biometric information under 1798.140(c) |
| **Chile Neurorights Law** | Organ tissue data — the highest protection classification, categorically different from general personal data |
| **HIPAA** (US) | Protected Health Information (PHI) when associated with identifiable individuals in covered entity contexts |
| **UNESCO Recommendation** | Neural data requiring specific ethical governance beyond general data protection |

### 4.3 Do NOT Scan If

**Do not use this tool to scan files containing:**

- **Real patient data** (PHI under HIPAA, patient records, clinical trial data)
- **IRB-restricted research data** (human subjects data governed by institutional review board protocols)
- **Identifiable neural recordings** (EEG/ECoG/LFP files with subject identifiers in headers, filenames, or metadata)
- **Proprietary clinical protocols** (treatment algorithms, device firmware, trade secrets)

**...unless your institution's data governance policy explicitly permits sending this data to your AI platform provider** and you have verified that:

1. Your AI platform provider's privacy policy covers this data category
2. A Data Processing Agreement (DPA) is in place covering special category/sensitive data
3. If applicable, a Business Associate Agreement (BAA) is in place for HIPAA-covered data
4. Your IRB approval (if applicable) covers AI-assisted analysis of the research data

### 4.4 Report Sanitization

This plugin instructs the AI agent to sanitize generated reports by:

- Replacing absolute file paths with relative paths
- Redacting API keys, tokens, and credentials with `[REDACTED]`
- Removing hostnames, IP addresses, and internal URLs
- Excluding raw neural data samples, patient names, and subject identifiers
- Omitting organization names unless explicitly opted in

**This sanitization is performed by the AI following instructions, not by a deterministic code filter.** It is a best-effort process. False negatives (missed sensitive data) are possible.

**Always review generated reports before sharing externally.**

### 4.5 PII Detection Limitations

The PII detection engine uses regex pattern matching. Pattern matching:

- **Produces false positives:** Non-PII that matches patterns (e.g., test email addresses, example SSN formats) will be flagged
- **Produces false negatives:** PII in unexpected formats, obfuscated PII, or PII in languages other than English may not be detected
- **Is not comprehensive:** New PII types, custom identifier formats, and context-dependent identifiers may not be covered
- **Does not validate:** A pattern match indicates a potential finding, not a confirmed PII instance

**Do not rely on this tool as your sole PII detection mechanism.** Use it as one layer in a defense-in-depth approach alongside dedicated data loss prevention (DLP) tools, manual review, and organizational data governance procedures.

## 5. Limitation of Liability

**TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW:**

This tool is provided "AS IS" and "AS AVAILABLE" without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, completeness, or non-infringement.

The authors and contributors of BCI Security Tools shall not be liable for any direct, indirect, incidental, special, consequential, or punitive damages arising from:

- Use or inability to use this tool
- Reliance on any output, findings, scores, or recommendations produced by this tool
- Any regulatory enforcement action, fine, penalty, or liability arising from use of this tool's output in compliance determinations
- Any clinical harm, patient safety incident, or adverse event related to decisions informed by this tool's output
- Data breaches or privacy incidents arising from the data flow described in Section 4.1
- False positives or false negatives in PII detection, threat identification, or compliance assessment
- Any action or inaction taken based on this tool's output

**You are solely responsible for:**

- Validating all findings independently before acting on them
- Ensuring your use of this tool complies with applicable data protection regulations
- Reviewing all generated reports before sharing externally
- Obtaining qualified professional advice (legal, security, clinical) before making decisions based on this tool's output

## 6. Regulatory Framework Status

| Framework | Status | Binding? |
|-----------|--------|----------|
| **GDPR** | Enacted (2018) | Yes — EU/EEA |
| **CCPA/CPRA** | Enacted (2020/2023) | Yes — California |
| **Chile Neurorights Law** | Enacted (2021 constitutional amendment, 2024 implementing law) | Yes — Chile |
| **UNESCO Recommendation** | Adopted/In development (2024-2025) | Non-binding but normative |
| **MIND Act** | Proposed | Not enacted — referenced for forward-looking compliance planning only |
| **HIPAA** | Enacted (1996, amended) | Yes — US covered entities and business associates |

References to proposed or draft legislation are included for forward-looking compliance planning. They do not imply that such legislation has been enacted or that compliance is currently required.

## 7. Intellectual Property

- **Code and skill definitions:** Apache License 2.0 (see `LICENSE-CODE`)
- **Data** (TARA catalog, NISS scores, guardrails, PII patterns, regulatory mappings, sample configs): Creative Commons Attribution 4.0 International (see `LICENSE-DATA`)

## 8. Contact

For questions about this tool's legal notices, privacy practices, or to report a security vulnerability:

- **Repository:** github.com/qinnovates/bci-security
- **Organization:** QInnovate (qinnovate.com)

---

*This document is provided for informational purposes and does not create an attorney-client relationship. If you have specific legal questions about your use of this tool, consult a qualified attorney in your jurisdiction.*
