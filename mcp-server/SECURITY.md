# MCP Server Security Architecture

## Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  MCP Client (Cursor, Claude Desktop, VS Code, etc.) │
│                                                     │
│  ┌─ User Code ──────────────────────────────────┐   │
│  │  Files, configs, neural data                 │   │
│  │  UNTRUSTED — user reads file, passes as str  │   │
│  └──────────────────────────────────────────────┘   │
│                    │                                │
│         MCP Protocol (stdio/JSON-RPC)               │
│                    │                                │
├────────────────────┼────────────────────────────────┤
│                    ▼                                │
│  ┌─ BCI Security MCP Server ────────────────────┐   │
│  │                                              │   │
│  │  ┌─ Input Gate ──────────────────────────┐   │   │
│  │  │  Zod schema validation                │   │   │
│  │  │  Injection detection (17 triggers)    │   │   │
│  │  │  Control character stripping          │   │   │
│  │  └───────────────────────────────────────┘   │   │
│  │              │                               │   │
│  │  ┌─ Tool Logic ──────────────────────────┐   │   │
│  │  │  8 tools: tara_lookup, niss_score,    │   │   │
│  │  │  bci_scan, bci_compliance,            │   │   │
│  │  │  bci_threat_model, bci_anonymize,     │   │   │
│  │  │  neuromodesty_check, bci_learn        │   │   │
│  │  └───────────────────────────────────────┘   │   │
│  │              │                               │   │
│  │  ┌─ Output Gate ─────────────────────────┐   │   │
│  │  │  Credential redaction (10 patterns)   │   │   │
│  │  │  Path sanitization (absolute → [path])│   │   │
│  │  │  IP/hostname stripping                │   │   │
│  │  │  Self-verification pass               │   │   │
│  │  └───────────────────────────────────────┘   │   │
│  │              │                               │   │
│  │  ┌─ Data Layer (read-only) ──────────────┐   │   │
│  │  │  7 JSON files loaded at startup       │   │   │
│  │  │  Cached in memory                     │   │   │
│  │  │  Path-guarded: data/ dir only         │   │   │
│  │  │  TRUSTED for data, UNTRUSTED for      │   │   │
│  │  │  injection (supply chain defense)     │   │   │
│  │  └───────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Threat Model

### What the server does NOT do
- **No file system writes.** Read-only access to its own data directory.
- **No network calls.** Zero HTTP, WebSocket, DNS, or socket operations.
- **No shell execution.** No `child_process`, `exec`, `spawn`, or `os.system`.
- **No dynamic code evaluation.** No `eval()`, `new Function()`, or `vm.runInContext()`.
- **No user-supplied file paths.** Code/content is passed as string arguments. The server never opens files on behalf of the user.

### Attack surfaces

| Surface | Risk | Mitigation |
|---------|------|------------|
| Tool input strings | Prompt injection, oversized input | Zod validation (max lengths), injection keyword detection, control char stripping |
| Tool input strings | Credential leakage (user passes code with secrets) | Immediate redaction at scan time via 10 credential regex patterns |
| Data files (supply chain) | Poisoned JSON could contain injection payloads | Data file fields treated as untrusted for injection purposes, even though data content is trusted |
| MCP transport (stdio) | Malformed JSON-RPC | SDK handles protocol validation |
| Output | Credential/PII leakage in reports | 7-rule sanitization + self-verification pass |
| Dependencies | Compromised npm packages | Only 2 runtime deps (MCP SDK, Zod). Both well-maintained. `npm audit` clean. |

### Supply chain

**Runtime dependencies (2):**
- `@modelcontextprotocol/sdk` — Anthropic-maintained MCP protocol implementation
- `zod` — Schema validation, 45k+ GitHub stars, Colin McDonnell

**Dev dependencies (3):**
- `typescript`, `tsx`, `@types/node` — standard TypeScript toolchain

No transitive dependencies with known vulnerabilities as of build date.

## Security Controls by Layer

### Layer 1: Input Validation (`security/validator.ts`)
- Zod schemas for all 8 tools
- Max string lengths enforced (200 chars for queries, 100KB for code, 50KB for text)
- Enum validation for all categorical inputs
- Control characters stripped from all string inputs

### Layer 2: Injection Detection (`security/injection.ts`)
- 17 canonical trigger phrases (case-insensitive, NFKC-normalized)
- Applied to all user-supplied string fields before processing
- Throws with descriptive error on detection (does not silently continue)

### Layer 3: Credential Redaction (`security/credentials.ts`)
- 10 regex patterns (AWS, Stripe, Slack, GitHub, GitLab, PEM, JWT, generic API keys/tokens)
- Applied at detection time (during scanning), not at output time
- Fresh regex instances per call (no stale `lastIndex` state)
- **No opt-out.** No flag disables this.

### Layer 4: Output Sanitization (`security/sanitizer.ts`)
- 7 rules from SAFETY.md Section 4
- Absolute paths always stripped (even with `--include-paths`)
- Credentials re-checked at output time (defense in depth)
- IP addresses replaced with `[device-ip]`
- Self-verification pass after all rules applied

### Layer 5: Path Guard (`security/path-guard.ts`)
- Data directory resolved at startup via `path.resolve()`
- Null bytes rejected
- Path traversal (`..`) rejected
- Absolute paths rejected
- Subdirectories rejected (flat file access only)
- Resolved path verified to be within data directory

## Incident Response

If a vulnerability is discovered in this server:

1. **Do not open a public issue.** Email security concerns to the maintainers.
2. **Scope:** This server has no network access and no file write capability. The blast radius of any vulnerability is limited to information disclosure from the bundled data files (which are public) or from user-supplied code strings (which the user already has access to).
3. **Updates:** Pin to specific versions. Check release notes before upgrading.
