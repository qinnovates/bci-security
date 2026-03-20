/**
 * Data loader — loads all JSON data files at startup, caches in memory.
 * Uses path-guard to ensure we only read from the data directory.
 */

import { readFileSync } from "node:fs";
import { resolveDataPath } from "../security/path-guard.js";
import type {
  TaraData,
  NissDeviceData,
  PiiData,
  GuardrailData,
  ComplianceData,
  SecurityControlsData,
  HardrailsData,
} from "../types/index.js";

// In-memory cache — loaded once at startup
let taraData: TaraData | null = null;
let nissDeviceData: NissDeviceData | null = null;
let piiData: PiiData | null = null;
let guardrailData: GuardrailData | null = null;
let complianceData: ComplianceData | null = null;
let securityControlsData: SecurityControlsData | null = null;
let hardrailsData: HardrailsData | null = null;

function loadJson<T>(filename: string): T {
  const filepath = resolveDataPath(filename);
  const raw = readFileSync(filepath, "utf-8");
  return JSON.parse(raw) as T;
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
