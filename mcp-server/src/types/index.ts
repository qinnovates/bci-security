/**
 * Type definitions for BCI security data files.
 * Derived from the JSON schema of each data file.
 */

// --- TARA Techniques ---

export interface NissVector {
  vector: string;
  score: number;
  severity: "none" | "low" | "medium" | "high" | "critical";
}

export interface TaraTechnique {
  id: string;
  name: string;
  tactic: string;
  bands: string;
  status: "CONFIRMED" | "DEMONSTRATED" | "EMERGING" | "PROJECTED" | "THEORETICAL";
  severity: "low" | "medium" | "high" | "critical";
  niss: NissVector;
  mechanism: string;
  sources: string[];
  dual_use: "confirmed" | "probable" | "possible" | "none";
  therapeutic_analog: string;
  mitigations: string[];
}

export interface TaraData {
  version: string;
  total: number;
  _schema_notes: string;
  techniques: TaraTechnique[];
}

// --- NISS Device Scores ---

export interface NissDeviceDetails {
  score: number;
  n_techniques: number | string;
}

export interface NissDevice {
  device: string;
  type: "invasive" | "non-invasive" | "semi-invasive";
  purpose: "medical" | "consumer" | "research" | "military";
  n_techniques: number;
  overall_score: number;
  severity: string;
  subscores: Record<string, number>;
  details: Record<string, NissDeviceDetails>;
  vector: string;
}

export interface NissDeviceData {
  version: string;
  devices: NissDevice[];
}

// --- PII Patterns ---

export interface PiiCategory {
  label: string;
  description: string;
  severity: "critical" | "high" | "medium";
  regulations: string[];
}

export interface PiiPattern {
  id: string;
  name: string;
  category: string;
  pattern: string;
  pattern_broad?: string;
  context: string[];
  context_filter?: string;
  severity: "critical" | "high" | "medium";
  description: string;
  remediation: string;
  regulations: string[];
  check_type?: string;
  sidecar_pattern?: string;
}

export interface PiiData {
  _metadata: { title: string; version: string; description: string; license: string };
  categories: Record<string, PiiCategory>;
  patterns: PiiPattern[];
  regulatory_frameworks: Record<string, unknown>;
}

// --- Guardrails ---

export interface GuardrailSource {
  author: string;
  year: number;
  work: string;
  journal: string;
  researchSourceId: string | null;
}

export interface Guardrail {
  id: string;
  name: string;
  category: "overclaim" | "methodology" | "framing";
  source: GuardrailSource;
  neuroethics: {
    constraint: string;
    violation: string;
    correct: string;
  };
  neurosecurity: {
    scope: string;
    components: string[];
  };
}

export interface GuardrailData {
  metadata: { version: string; description: string; totalGuardrails: number };
  guardrails: Guardrail[];
  componentBounds: Array<{
    component: string;
    fullName: string;
    does: string;
    doesNot: string[];
    guardrails: string[];
    status: string;
  }>;
}

// --- Regulatory Compliance ---

export interface ComplianceRequirement {
  id: string;
  requirement: string;
  description: string;
  check: string;
  severity: "critical" | "high" | "medium";
  regulations: string[];
  evidence: string[];
}

export interface ComplianceDomain {
  id: string;
  domain: string;
  description: string;
  requirements: ComplianceRequirement[];
}

export interface ComplianceData {
  _metadata: { title: string; version: string; description: string };
  compliance_domains: ComplianceDomain[];
}

// --- Security Controls ---

export interface BandControls {
  detection: string[];
  prevention: string[];
  response: string[];
}

export interface NspLayer {
  layer: number;
  name: string;
  bands: string[];
  overhead: string;
}

export interface SecurityControlsData {
  _metadata: { title: string; version: string; description: string };
  controls_by_band: Record<string, BandControls>;
  nsp_layers: NspLayer[];
}

// --- Hardrails ---

export interface HardrailsData {
  _metadata: { title: string; version: string; description: string };
  guardrails: {
    description: string;
    layers: Array<{ id: string; name: string; description: string; enforcement: string }>;
  };
  hardening: {
    description: string;
    layers: Array<{ id: string; name: string; description: string; enforcement: string }>;
  };
}

// --- Security Scan Patterns (OWASP/CWE/Burp) ---

export interface SecurityScanPattern {
  id: string;
  name: string;
  category: string;
  owasp?: string;
  cwe: string;
  pattern: string;
  severity: "critical" | "high" | "medium" | "low";
  context: string[];
  description: string;
  remediation: string;
}

export interface SecurityScanData {
  _metadata: { title: string; version: string; description: string; sources: string[] };
  categories: Record<string, { label: string; description: string }>;
  patterns: SecurityScanPattern[];
}

// --- Tool Result ---

export interface ToolResult {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}
