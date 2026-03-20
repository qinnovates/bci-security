/**
 * Path traversal prevention — implements SAFETY.md Section 6.
 * The MCP server only reads from its own data directory. Nothing else.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Data directory: mcp-server/src/security -> ../../data (the shared data/ dir)
const DATA_DIR = path.resolve(__dirname, "..", "..", "..", "data");

/**
 * Resolve a data filename to an absolute path within the data directory.
 * Rejects any path traversal attempts.
 */
export function resolveDataPath(filename: string): string {
  // Reject null bytes
  if (filename.includes("\0")) {
    throw new Error("Invalid filename: null bytes are not allowed");
  }

  // Reject path traversal components
  if (filename.includes("..") || path.isAbsolute(filename)) {
    throw new Error("Invalid filename: path traversal is not allowed");
  }

  // Reject path separators — we only load known filenames
  if (filename.includes("/") || filename.includes("\\")) {
    throw new Error("Invalid filename: subdirectories are not allowed");
  }

  const resolved = path.resolve(DATA_DIR, filename);

  // Use path.relative to check containment — works correctly on case-insensitive filesystems
  const relative = path.relative(DATA_DIR, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Resolved path escapes the data directory");
  }

  return resolved;
}

/**
 * Get the data directory path for startup validation.
 */
export function getDataDir(): string {
  return DATA_DIR;
}
