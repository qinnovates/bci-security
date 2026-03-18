# Contributing to BCI Security

Contributions welcome. This guide covers how to add new content to each data layer.

## Adding a TARA Technique

Edit `data/tara-techniques.json`. Each technique requires ALL of these fields:

```json
{
  "id": "QIF-T0136",
  "name": "Technique name (lowercase, descriptive)",
  "tactic": "QIF-X.YZ",
  "bands": "I0–N1",
  "status": "CONFIRMED|DEMONSTRATED|EMERGING|THEORETICAL|PLAUSIBLE|SPECULATIVE",
  "severity": "critical|high|medium|low",
  "niss": {
    "vector": "NISS:1.1/BI:N/CR:N/CD:N/CV:N/RV:F/NP:N",
    "score": 0.0,
    "severity": "low|medium|high|critical"
  },
  "mechanism": "One-sentence physical description of the attack mechanism",
  "sources": ["Author et al. YYYY"],
  "dual_use": "confirmed|probable|possible|silicon_only",
  "therapeutic_analog": "Name of therapeutic treatment or null",
  "mitigations": ["mitigation_id_1", "mitigation_id_2"]
}
```

**Severity fields:** Each technique has TWO severity assessments. `severity` is editorial (tactical impact if it succeeds). `niss.severity` is computed from the NISS vector (biological signal disruption). These may differ and that's intentional.

**Evidence tiers:**
- CONFIRMED — independently reproduced in published, peer-reviewed research
- DEMONSTRATED — lab-proven, published but not independently replicated
- EMERGING — active research with partial evidence
- THEORETICAL — physics supports it, no demonstration
- PLAUSIBLE — reasonable extrapolation
- SPECULATIVE — edge case, limited evidence

**Tactic codes:** Must match an existing tactic (QIF-N.IJ, QIF-N.MD, QIF-N.SC, QIF-D.HV, QIF-C.EX, QIF-C.IM, QIF-P.DS, QIF-M.SV, QIF-E.RD, QIF-B.IN, QIF-B.EV, QIF-S.HV, QIF-S.FP, QIF-S.RP, QIF-S.CH, QIF-S.SC).

**After adding:** Update `total` in the JSON metadata. Verify the technique appears in `/bci explain <ID>`.

## Adding a PII Detection Pattern

Edit `data/pii-patterns.json`. Each pattern requires:

```json
{
  "id": "PII-019",
  "name": "Short descriptive name",
  "category": "direct_identifiers|neural_identifiers|quasi_identifiers|health_identifiers|consent_gaps|retention_violations",
  "pattern": "PCRE-compatible regex",
  "context": ["code", "config", "filename", "header", "metadata"],
  "severity": "critical|high|medium|low",
  "description": "What this pattern detects and why it matters",
  "remediation": "Specific fix instructions",
  "regulations": ["GDPR Art.X", "CCPA 1798.XXX"]
}
```

**Optional fields:** `context_filter` (when to suppress false positives), `pattern_broad` (secondary broader pattern), `check_type` and `sidecar_pattern` (for sidecar file checks).

## Adding a Compliance Framework

Edit `data/regulatory-compliance.json`. Add a new framework object to the `regulatory_frameworks` section:

```json
{
  "full_name": "Official Name (Year)",
  "jurisdiction": "Where it applies",
  "neural_data_classification": "How this framework classifies neural data",
  "key_articles": ["Art.X — description"],
  "bci_relevance": "Why this matters for BCI",
  "status": "Enacted|Proposed|Non-binding"
}
```

Then add corresponding requirements to the `compliance_domains` array and update any PII patterns that should reference the new framework.

## Adding Security Controls

Edit `data/security-controls.json`. Controls are organized by QIF hourglass band (N7 through S3). Add new controls under the appropriate band with detection signals and evidence tier.

## Testing Your Changes

After any data change, verify:

1. `/bci-scan --demo` still produces a complete report
2. `/bci compliance --demo` still runs without errors
3. `/bci explain <your-new-ID>` returns the correct technique
4. `/bci learn tara` mentions the new content if applicable

## Security Requirements

All data file content is treated as untrusted for prompt injection purposes (see `docs/SAFETY.md` Section 1). Do not include instruction-like text in technique names, descriptions, or source fields.

## Code of Conduct

Be accurate. Cite real sources. Mark speculative techniques appropriately. Follow the neuromodesty guardrails — no overclaims.

## License

- Code contributions (SKILL.md, commands, scripts): Apache 2.0
- Data contributions (JSON): CC BY 4.0
