/**
 * MCP Resource definitions — expose data files as read-only resources.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  getTara,
  getNissDevices,
  getPii,
  getGuardrails,
  getCompliance,
  getSecurityControls,
  getHardrails,
} from "../data/loader.js";

interface ResourceDef {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
  getData: () => unknown;
}

const RESOURCES: ResourceDef[] = [
  {
    uri: "bci://data/tara-techniques",
    name: "TARA Technique Catalog",
    description:
      "Complete catalog of BCI threat techniques with NISS scores, mechanisms, and mitigations. " +
      "Proposed research tool (unvalidated, in development).",
    mimeType: "application/json",
    getData: () => getTara(),
  },
  {
    uri: "bci://data/pii-patterns",
    name: "PII Detection Patterns",
    description:
      "18 regex patterns for detecting personally identifiable information in BCI data pipelines, " +
      "mapped to regulatory frameworks (GDPR, CCPA, Chile Neurorights, UNESCO, Mind Act, HIPAA).",
    mimeType: "application/json",
    getData: () => getPii(),
  },
  {
    uri: "bci://data/niss-device-scores",
    name: "NISS Device Scores",
    description:
      "Pre-computed NISS severity scores for BCI devices (NSv2.1). " +
      "Proposed scoring system (unvalidated, in development).",
    mimeType: "application/json",
    getData: () => getNissDevices(),
  },
  {
    uri: "bci://data/regulatory-compliance",
    name: "Regulatory Compliance Requirements",
    description:
      "BCI compliance requirements across GDPR, CCPA, Chile Neurorights, UNESCO, Mind Act, and HIPAA. " +
      "Research reference, not legal advice.",
    mimeType: "application/json",
    getData: () => getCompliance(),
  },
  {
    uri: "bci://data/guardrails",
    name: "Neuroethics Guardrails",
    description:
      "8 neuroethics guardrails from published literature (Morse, Poldrack, Racine, Ienca, " +
      "Kellmeyer, Wexler, Tennison, Vul/Eklund) with QIF scope mappings.",
    mimeType: "application/json",
    getData: () => getGuardrails(),
  },
  {
    uri: "bci://data/security-controls",
    name: "Security Controls by QIF Band",
    description:
      "Detection, prevention, and response controls mapped to QIF hourglass bands (N7-S3).",
    mimeType: "application/json",
    getData: () => getSecurityControls(),
  },
  {
    uri: "bci://data/hardrails",
    name: "Security Hardrails Framework",
    description:
      "Combined guardrails (ethical constraints) + hardening (technical enforcement) model.",
    mimeType: "application/json",
    getData: () => getHardrails(),
  },
];

export function registerResources(server: Server): void {
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: RESOURCES.map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description,
      mimeType: r.mimeType,
    })),
  }));

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const resource = RESOURCES.find((r) => r.uri === request.params.uri);
    if (!resource) {
      throw new Error(`Resource not found: ${request.params.uri}`);
    }

    return {
      contents: [
        {
          uri: resource.uri,
          mimeType: resource.mimeType,
          text: JSON.stringify(resource.getData(), null, 2),
        },
      ],
    };
  });
}
