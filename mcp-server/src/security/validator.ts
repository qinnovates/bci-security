/**
 * Central Zod schemas for all tool inputs — implements SAFETY.md Section 7.
 * Every tool input is validated before any processing occurs.
 */

import { z } from "zod";

// --- Shared constraints ---

// Strip C0 control chars, DEL, Unicode bidi overrides (U+202A-202E, U+2066-2069),
// and zero-width characters (U+200B-200D, U+FEFF) that can bypass injection detection
const UNSAFE_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200d\u202a-\u202e\u2066-\u2069\ufeff]/g;

const safeString = (maxLen: number) =>
  z.string().min(1).max(maxLen).transform((s) => s.replace(UNSAFE_CHARS, ""));

// Code strings: strip bidi/zero-width (which can hide injection) but keep other control chars
const codeString = () =>
  z.string().min(1).max(100_000).transform((s) => s.replace(/[\u200b-\u200d\u202a-\u202e\u2066-\u2069\ufeff]/g, ""));

// --- Tool Schemas ---

export const TaraLookupSchema = z.object({
  query: safeString(200),
  search_by: z
    .enum(["id", "keyword", "severity", "status", "tactic", "band"])
    .default("keyword"),
  limit: z.number().int().min(1).max(50).default(10),
});
export type TaraLookupInput = z.infer<typeof TaraLookupSchema>;

export const NissScoreSchema = z.object({
  query: safeString(200),
  mode: z.enum(["technique", "device", "compare", "explain"]).default("technique"),
});
export type NissScoreInput = z.infer<typeof NissScoreSchema>;

export const BciScanSchema = z.object({
  code: codeString(),
  filename: safeString(255).optional(),
  language: z
    .enum(["python", "javascript", "typescript", "matlab", "c", "cpp", "unknown"])
    .default("unknown"),
});
export type BciScanInput = z.infer<typeof BciScanSchema>;

export const BciComplianceSchema = z.object({
  mode: z.enum(["scan", "assess", "frameworks"]),
  code: codeString().optional(),
  filename: safeString(255).optional(),
  framework: z
    .enum(["all", "gdpr", "ccpa", "chile", "unesco", "mind_act", "hipaa"])
    .default("all"),
});
export type BciComplianceInput = z.infer<typeof BciComplianceSchema>;

export const BciThreatModelSchema = z.object({
  device_class: z.enum([
    "consumer_eeg",
    "research_eeg",
    "implanted_bci",
    "neurostimulation",
    "neurofeedback",
    "other",
  ]),
  signal_types: z.array(safeString(50)).min(1).max(20),
  connectivity: z
    .array(z.enum(["bluetooth_classic", "ble", "wifi", "usb", "cloud_api", "wired_only"]))
    .min(1),
  deployment_context: z.enum(["clinical", "consumer", "research", "military"]),
  existing_controls: z.array(safeString(100)).max(50).optional(),
  device_name: safeString(100).optional(),
});
export type BciThreatModelInput = z.infer<typeof BciThreatModelSchema>;

export const BciAnonymizeSchema = z.object({
  mode: z.enum(["scan", "check", "template"]),
  content: codeString().optional(),
  filename: safeString(255).optional(),
  format: z
    .enum(["edf", "bdf", "xdf", "fif", "nwb", "gdf", "csv", "mat", "unknown"])
    .optional(),
});
export type BciAnonymizeInput = z.infer<typeof BciAnonymizeSchema>;

export const NeuromodestyCheckSchema = z.object({
  text: z.string().min(1).max(50_000).transform((s) => s.replace(UNSAFE_CHARS, "")),
  include_qif_checks: z.boolean().default(true),
});
export type NeuromodestyCheckInput = z.infer<typeof NeuromodestyCheckSchema>;

export const BciLearnSchema = z.object({
  topic: z.enum(["quickstart", "tara", "ttp", "clinical", "niss", "neuroethics"]),
  step: z.number().int().min(1).max(10).optional(),
});
export type BciLearnInput = z.infer<typeof BciLearnSchema>;
