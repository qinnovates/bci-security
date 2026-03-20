#!/usr/bin/env node

/**
 * BCI Security MCP Server
 *
 * Provides BCI threat modeling, vulnerability scanning, and neuroethics compliance
 * tools via the Model Context Protocol. Works with any MCP-compatible client.
 *
 * Security model:
 * - No file system access beyond the bundled data directory
 * - No network calls
 * - No shell execution
 * - All inputs validated with Zod
 * - All outputs sanitized (credentials redacted, paths stripped)
 * - Prompt injection detection on all user-supplied strings
 */

import { z } from "zod";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { loadAllData } from "./data/loader.js";
import { registerResources } from "./resources/index.js";
import { auditToolCall } from "./security/audit.js";

// Tool implementations
import { taraLookup } from "./tools/tara-lookup.js";
import { nissScore } from "./tools/niss-score.js";
import { bciScan } from "./tools/bci-scan.js";
import { bciCompliance } from "./tools/bci-compliance.js";
import { bciThreatModel } from "./tools/bci-threat-model.js";
import { bciAnonymize } from "./tools/bci-anonymize.js";
import { neuromodestyCheck } from "./tools/neuromodesty-check.js";
import { bciLearn } from "./tools/bci-learn.js";
import { securityToolStatus, runDastScan, runSupplyChainScan } from "./tools/security-orchestrator.js";

// Input validators
import {
  TaraLookupSchema,
  NissScoreSchema,
  BciScanSchema,
  BciComplianceSchema,
  BciThreatModelSchema,
  BciAnonymizeSchema,
  NeuromodestyCheckSchema,
  BciLearnSchema,
} from "./security/validator.js";

import type { ToolResult } from "./types/index.js";

const SERVER_NAME = "bci-security";
const SERVER_VERSION = "1.0.0";

// Tool definitions
const TOOLS = [
  {
    name: "tara_lookup",
    description:
      "Search the TARA catalog of BCI threat techniques. Query by ID, keyword, severity, status, tactic, or QIF band. " +
      "Returns technique details including NISS scores, mechanisms, and mitigations. " +
      "TARA is a proposed research catalog (unvalidated, in development).",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (technique ID, keyword, severity level, etc.)" },
        search_by: {
          type: "string",
          enum: ["id", "keyword", "severity", "status", "tactic", "band"],
          default: "keyword",
          description: "What field to search by",
        },
        limit: { type: "number", default: 10, description: "Max results to return (1-50)" },
      },
      required: ["query"],
    },
  },
  {
    name: "niss_score",
    description:
      "Look up NISS severity scores for BCI threats or devices. Modes: technique (by ID/name), " +
      "device (by device name), compare (A vs B), explain (NISS vector format). " +
      "NISS is a proposed scoring system (unvalidated, in development).",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Technique ID/name, device name, or 'A vs B' for compare" },
        mode: {
          type: "string",
          enum: ["technique", "device", "compare", "explain"],
          default: "technique",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "bci_scan",
    description:
      "Scan code for BCI security anti-patterns. Detects: unencrypted transport, exposed credentials, " +
      "PII in neural data pipelines, and hardcoded secrets. Pass code as a string (not a file path). " +
      "Pattern-matching only, not static analysis.",
    inputSchema: {
      type: "object" as const,
      properties: {
        code: { type: "string", description: "Code to scan (as a string, not a file path)" },
        filename: { type: "string", description: "Original filename (for context, not accessed)" },
        language: {
          type: "string",
          enum: ["python", "javascript", "typescript", "matlab", "c", "cpp", "unknown"],
          default: "unknown",
        },
      },
      required: ["code"],
    },
  },
  {
    name: "bci_compliance",
    description:
      "Assess BCI systems against regulatory frameworks (GDPR, CCPA, Chile Neurorights, UNESCO, Mind Act, HIPAA). " +
      "Modes: scan (code analysis), assess (questionnaire), frameworks (list all requirements). " +
      "Research reference, not legal advice.",
    inputSchema: {
      type: "object" as const,
      properties: {
        mode: { type: "string", enum: ["scan", "assess", "frameworks"] },
        code: { type: "string", description: "Code to scan (for scan mode)" },
        filename: { type: "string", description: "Original filename (for context)" },
        framework: {
          type: "string",
          enum: ["all", "gdpr", "ccpa", "chile", "unesco", "mind_act", "hipaa"],
          default: "all",
        },
      },
      required: ["mode"],
    },
  },
  {
    name: "bci_threat_model",
    description:
      "Generate a structured BCI threat model. Provide a device profile to get relevant TARA techniques, " +
      "NISS scores, risk matrix, and mitigation recommendations. " +
      "Proposed research tool, not a substitute for professional security assessment.",
    inputSchema: {
      type: "object" as const,
      properties: {
        device_class: {
          type: "string",
          enum: ["consumer_eeg", "research_eeg", "implanted_bci", "neurostimulation", "neurofeedback", "other"],
        },
        signal_types: {
          type: "array",
          items: { type: "string" },
          description: "Signal types (e.g., EEG, ECoG, LFP, EMG)",
        },
        connectivity: {
          type: "array",
          items: {
            type: "string",
            enum: ["bluetooth_classic", "ble", "wifi", "usb", "cloud_api", "wired_only"],
          },
        },
        deployment_context: {
          type: "string",
          enum: ["clinical", "consumer", "research", "military"],
        },
        existing_controls: {
          type: "array",
          items: { type: "string" },
          description: "Controls already in place",
        },
        device_name: { type: "string", description: "Device name (optional)" },
      },
      required: ["device_class", "signal_types", "connectivity", "deployment_context"],
    },
  },
  {
    name: "bci_anonymize",
    description:
      "Detect PII in neural data content or filenames. Checks against 18 PII patterns mapped to " +
      "regulatory frameworks. Modes: scan (content analysis), check (filename only), template (BIDS/consent templates). " +
      "Pass content as a string, not a file path.",
    inputSchema: {
      type: "object" as const,
      properties: {
        mode: { type: "string", enum: ["scan", "check", "template"] },
        content: { type: "string", description: "File content to scan (for scan mode)" },
        filename: { type: "string", description: "Filename to check for PII (for check mode)" },
        format: {
          type: "string",
          enum: ["edf", "bdf", "xdf", "fif", "nwb", "gdf", "csv", "mat", "unknown"],
          description: "Neural data format",
        },
      },
      required: ["mode"],
    },
  },
  {
    name: "neuromodesty_check",
    description:
      "Check text for neuroethics overclaims against 8 published guardrails (G1-G8). " +
      "Detects causal overclaims, reverse inference, neurorealism, brain reading limits violations, " +
      "and QIF status misrepresentation. Returns violations with corrected versions.",
    inputSchema: {
      type: "object" as const,
      properties: {
        text: { type: "string", description: "Text to check for overclaims" },
        include_qif_checks: {
          type: "boolean",
          default: true,
          description: "Also check QIF/TARA/NISS status claims",
        },
      },
      required: ["text"],
    },
  },
  {
    name: "bci_learn",
    description:
      "Interactive educational walkthroughs for BCI security concepts. " +
      "Topics: quickstart, tara, ttp, clinical, niss, neuroethics. " +
      "Each topic has multiple steps. Educational content only.",
    inputSchema: {
      type: "object" as const,
      properties: {
        topic: {
          type: "string",
          enum: ["quickstart", "tara", "ttp", "clinical", "niss", "neuroethics"],
        },
        step: { type: "number", description: "Step number (starts at 1)", default: 1 },
      },
      required: ["topic"],
    },
  },
  {
    name: "dast_scan",
    description:
      "Run a dynamic application security test (DAST) against a target URL. " +
      "Uses Nuclei (9000+ templates, -ni flag to prevent OAST phone-home) and " +
      "Nikto (web server scanner, -nocheck). Makes live HTTP requests to the target. " +
      "Blocks scanning of internal/private IPs.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target_url: { type: "string", description: "Full URL to scan (e.g., https://api.example.com)" },
      },
      required: ["target_url"],
    },
  },
  {
    name: "supply_chain_scan",
    description:
      "Scan MCP server configs and dependencies for supply chain risks. " +
      "MCPShield (typosquatting, CVEs, credentials), SkillFortify (ASBOM, trust scores), " +
      "OpenSSF Scorecard (maintainer reputation). All run locally.",
    inputSchema: {
      type: "object" as const,
      properties: {
        config_path: {
          type: "string",
          description: "Path to MCP config file, project directory, or GitHub repo URL (for Scorecard)",
        },
      },
      required: [],
    },
  },
  {
    name: "security_tool_status",
    description:
      "Show which external security tools are installed and available. " +
      "Lists all SAST, SCA, secrets, DAST, and IaC tools. " +
      "Provides install commands for missing tools.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
] as const;

// Tool handler dispatch
type ToolHandler = (args: Record<string, unknown>) => ToolResult;

const TOOL_HANDLERS: Record<string, ToolHandler> = {
  tara_lookup: (args) => taraLookup(TaraLookupSchema.parse(args)),
  niss_score: (args) => nissScore(NissScoreSchema.parse(args)),
  bci_scan: (args) => bciScan(BciScanSchema.parse(args)),
  bci_compliance: (args) => bciCompliance(BciComplianceSchema.parse(args)),
  bci_threat_model: (args) => bciThreatModel(BciThreatModelSchema.parse(args)),
  bci_anonymize: (args) => bciAnonymize(BciAnonymizeSchema.parse(args)),
  neuromodesty_check: (args) => neuromodestyCheck(NeuromodestyCheckSchema.parse(args)),
  bci_learn: (args) => bciLearn(BciLearnSchema.parse(args)),
  dast_scan: (args) => {
    const parsed = z.object({ target_url: z.string().url() }).parse(args);
    return runDastScan(parsed.target_url);
  },
  supply_chain_scan: (args) => {
    const parsed = z.object({ config_path: z.string().max(500).optional() }).parse(args);
    return runSupplyChainScan(parsed.config_path);
  },
  security_tool_status: () => securityToolStatus(),
};

async function main(): Promise<void> {
  // Load all data files into memory at startup
  loadAllData();

  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {} } }
  );

  // Register tool list
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [...TOOLS],
  }));

  // Register tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const handler = TOOL_HANDLERS[name];

    if (!handler) {
      auditToolCall(name, {}, "error", "unknown-tool");
      return {
        content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }

    try {
      const result = handler(args ?? {});
      auditToolCall(name, args ?? {}, "ok");
      return result;
    } catch (error) {
      // Sanitize error messages to prevent internal path/detail leakage
      const rawMessage = error instanceof Error ? error.message : String(error);
      let safeMessage: string;

      if (error instanceof z.ZodError) {
        // Zod validation errors: summarize without exposing internal structure
        const fields = error.errors.map((e) => e.path.join(".") || "input").join(", ");
        safeMessage = `Invalid input: check ${fields}`;
      } else if (rawMessage.includes("Injection pattern detected")) {
        // Injection errors are already safe by design — but don't reveal trigger list
        safeMessage = "Input rejected: contains disallowed patterns";
      } else if (rawMessage.includes("Data not loaded") || rawMessage.includes("data is empty")) {
        safeMessage = "Internal server error: data unavailable";
      } else {
        // Strip any absolute paths from error messages
        safeMessage = rawMessage.replace(/\/[\w/.-]+/g, "[path]");
      }

      const errorType = error instanceof z.ZodError ? "validation" :
        rawMessage.includes("Injection") ? "injection" : "internal";
      auditToolCall(name, args ?? {}, "error", errorType);

      return {
        content: [{ type: "text" as const, text: `Error: ${safeMessage}` }],
        isError: true,
      };
    }
  });

  // Register resources
  registerResources(server);

  // Start server with stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Server failed to start:", error);
  process.exit(1);
});
