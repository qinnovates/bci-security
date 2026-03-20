/**
 * Data loader — loads all JSON data files at startup, caches in memory.
 * Uses path-guard to ensure we only read from the data directory.
 *
 * Security controls:
 * - File size limit (CWE-770): reject files > 10MB before parsing
 * - Data poisoning check (MCP03): scan loaded string fields for injection triggers
 * - Integrity validation: verify non-empty arrays after parse
 */

import { readFileSync, statSync } from "node:fs";
import { resolveDataPath } from "../security/path-guard.js";
import { detectInjection } from "../security/injection.js";
import { audit } from "../security/audit.js";
import { validatePatternBatch } from "../security/safe-regex.js";
import type {
  TaraData,
  NissDeviceData,
  PiiData,
  GuardrailData,
  ComplianceData,
  SecurityControlsData,
  HardrailsData,
  SecurityScanData,
} from "../types/index.js";

// In-memory cache — loaded once at startup
let taraData: TaraData | null = null;
let nissDeviceData: NissDeviceData | null = null;
let piiData: PiiData | null = null;
let guardrailData: GuardrailData | null = null;
let complianceData: ComplianceData | null = null;
let securityControlsData: SecurityControlsData | null = null;
let hardrailsData: HardrailsData | null = null;
let securityScanData: SecurityScanData | null = null;

const MAX_DATA_FILE_SIZE = 10 * 1024 * 1024; // 10MB

function loadJson<T>(filename: string): T {
  const filepath = resolveDataPath(filename);

  // CWE-770: Check file size before reading into memory
  const stat = statSync(filepath);
  if (stat.size > MAX_DATA_FILE_SIZE) {
    throw new Error(`Data file ${filename} exceeds size limit (${stat.size} > ${MAX_DATA_FILE_SIZE})`);
  }

  const raw = readFileSync(filepath, "utf-8");
  return JSON.parse(raw) as T;
}

/**
 * Scan all string fields in loaded data for injection triggers (MCP03: Tool Poisoning).
 * A compromised data file could contain LLM instruction patterns in technique names,
 * descriptions, or other fields that get reflected into tool output.
 */
function scanDataForPoisoning(data: unknown, path: string): void {
  if (typeof data === "string") {
    const results = detectInjection(data);
    if (results.length > 0) {
      const triggers = results.map((r) => r.trigger).join(", ");
      audit("data-poisoning", `Injection trigger in ${path}: ${triggers}`);
    }
    return;
  }
  if (Array.isArray(data)) {
    // Only scan first 50 items to avoid startup delay
    for (let i = 0; i < Math.min(data.length, 50); i++) {
      scanDataForPoisoning(data[i], `${path}[${i}]`);
    }
    return;
  }
  if (data !== null && typeof data === "object") {
    for (const [key, value] of Object.entries(data)) {
      scanDataForPoisoning(value, `${path}.${key}`);
    }
  }
}

/**
 * Load all data files into memory. Called once at server startup.
 * Throws on any load failure — the server should not start with missing data.
 */
export function loadAllData(): void {
  taraData = loadJson<TaraData>("tara-techniques.json");
  nissDeviceData = loadJson<NissDeviceData>("niss-device-scores.json");
  piiData = loadJson<PiiData>("pii-patterns.json");
  guardrailData = loadJson<GuardrailData>("guardrails.json");
  complianceData = loadJson<ComplianceData>("regulatory-compliance.json");
  securityControlsData = loadJson<SecurityControlsData>("security-controls.json");
  hardrailsData = loadJson<HardrailsData>("hardrails.json");
  securityScanData = loadJson<SecurityScanData>("security-scan-patterns.json");

  // Validate critical data is present
  if (!taraData.techniques || taraData.techniques.length === 0) {
    throw new Error("TARA techniques data is empty");
  }
  if (!nissDeviceData.devices || nissDeviceData.devices.length === 0) {
    throw new Error("NISS device data is empty");
  }
  if (!piiData.patterns || piiData.patterns.length === 0) {
    throw new Error("PII patterns data is empty");
  }
  if (!guardrailData.guardrails || guardrailData.guardrails.length === 0) {
    throw new Error("Guardrails data is empty");
  }
  if (!securityScanData.patterns || securityScanData.patterns.length === 0) {
    throw new Error("Security scan patterns data is empty");
  }

  // MCP03: Scan data files for tool poisoning (injection triggers in data)
  scanDataForPoisoning(taraData.techniques, "tara.techniques");
  scanDataForPoisoning(guardrailData.guardrails, "guardrails.guardrails");
  scanDataForPoisoning(piiData.patterns, "pii.patterns");

  // CWE-1333: Validate all regex patterns at startup to catch ReDoS
  const piiValidation = validatePatternBatch(piiData.patterns);
  if (piiValidation.rejected.length > 0) {
    audit("redos-check", `Rejected ${piiValidation.rejected.length} PII patterns: ${piiValidation.rejected.join(", ")}`);
  }
  const secValidation = validatePatternBatch(securityScanData.patterns);
  if (secValidation.rejected.length > 0) {
    audit("redos-check", `Rejected ${secValidation.rejected.length} security patterns: ${secValidation.rejected.join(", ")}`);
  }
  audit("redos-check", `Validated ${piiValidation.valid + secValidation.valid} regex patterns at startup`);

  audit("startup", `Data loaded: ${taraData.techniques.length} techniques, ${nissDeviceData.devices.length} devices, ${piiData.patterns.length} PII patterns, ${guardrailData.guardrails.length} guardrails, ${securityScanData.patterns.length} OWASP/CWE/Burp patterns`);
}

// Accessors with runtime null checks
export function getTara(): TaraData {
  if (!taraData) throw new Error("Data not loaded. Call loadAllData() first.");
  return taraData;
}

export function getNissDevices(): NissDeviceData {
  if (!nissDeviceData) throw new Error("Data not loaded. Call loadAllData() first.");
  return nissDeviceData;
}

export function getPii(): PiiData {
  if (!piiData) throw new Error("Data not loaded. Call loadAllData() first.");
  return piiData;
}

export function getGuardrails(): GuardrailData {
  if (!guardrailData) throw new Error("Data not loaded. Call loadAllData() first.");
  return guardrailData;
}

export function getCompliance(): ComplianceData {
  if (!complianceData) throw new Error("Data not loaded. Call loadAllData() first.");
  return complianceData;
}

export function getSecurityControls(): SecurityControlsData {
  if (!securityControlsData) throw new Error("Data not loaded. Call loadAllData() first.");
  return securityControlsData;
}

export function getHardrails(): HardrailsData {
  if (!hardrailsData) throw new Error("Data not loaded. Call loadAllData() first.");
  return hardrailsData;
}

export function getSecurityScanPatterns(): SecurityScanData {
  if (!securityScanData) throw new Error("Data not loaded. Call loadAllData() first.");
  return securityScanData;
}
