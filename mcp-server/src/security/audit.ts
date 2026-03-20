/**
 * Structured audit logging — MCP08:2025.
 *
 * Logs to stderr (MCP spec permits this). Never logs sensitive input values.
 * Logs: tool name, timestamp, input field sizes, success/error status.
 */

interface AuditEntry {
  timestamp: string;
  event: string;
  detail: string;
}

/**
 * Write a structured audit log entry to stderr.
 * MCP servers may write to stderr for diagnostics — it does not interfere
 * with the stdio JSON-RPC transport on stdout.
 */
export function audit(event: string, detail: string): void {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    event,
    detail,
  };
  process.stderr.write(`[bci-security-audit] ${JSON.stringify(entry)}\n`);
}

/**
 * Log a tool invocation. Never logs input values — only field sizes.
 */
export function auditToolCall(
  toolName: string,
  args: Record<string, unknown>,
  status: "ok" | "error",
  errorType?: string
): void {
  const fieldSizes: Record<string, number | string> = {};
  for (const [key, value] of Object.entries(args)) {
    if (typeof value === "string") {
      fieldSizes[key] = value.length;
    } else if (Array.isArray(value)) {
      fieldSizes[key] = `array[${value.length}]`;
    } else {
      fieldSizes[key] = typeof value;
    }
  }

  audit("tool-call", JSON.stringify({
    tool: toolName,
    status,
    fieldSizes,
    ...(errorType ? { errorType } : {}),
  }));
}
