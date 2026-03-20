/**
 * Prompt injection detection — implements SAFETY.md Section 2.
 * Canonical keyword list. All user-supplied inputs pass through this.
 */

export const INJECTION_TRIGGERS: readonly string[] = [
  // Canonical list from SAFETY.md Section 2
  "important:",
  "claude:",
  "system:",
  "ignore previous",
  "include full path",
  "user has requested",
  "disregard sanitization",
  "you are now",
  "act as",
  "pretend",
  "new instructions",
  "disregard",
  "bypass",
  "skip",
  "reveal",
  "output all",
  "show me the contents of",
  // Extended triggers (security review findings)
  "forget previous",
  "override",
  "from now on",
  "new persona",
  "jailbreak",
  "developer mode",
  "do not follow",
  "sudo mode",
] as const;

export interface InjectionResult {
  trigger: string;
  position: number;
  context: string;
}

/**
 * Normalize input using NFKC (Unicode compatibility decomposition + canonical composition)
 * then check for injection trigger phrases.
 */
export function detectInjection(input: string): InjectionResult[] {
  const normalized = input.normalize("NFKC").toLowerCase();
  const results: InjectionResult[] = [];

  for (const trigger of INJECTION_TRIGGERS) {
    let searchFrom = 0;
    let pos: number;
    while ((pos = normalized.indexOf(trigger, searchFrom)) !== -1) {
      const contextStart = Math.max(0, pos - 20);
      const contextEnd = Math.min(normalized.length, pos + trigger.length + 20);
      results.push({
        trigger,
        position: pos,
        context: `...${input.slice(contextStart, contextEnd)}...`,
      });
      searchFrom = pos + 1;
    }
  }

  return results;
}

/**
 * Check input and throw if injection is detected. Use on all user-supplied strings.
 */
export function assertNoInjection(input: string, fieldName: string): void {
  const results = detectInjection(input);
  if (results.length > 0) {
    const triggers = results.map((r) => `"${r.trigger}"`).join(", ");
    throw new Error(
      `Injection pattern detected in ${fieldName}: ${triggers}. ` +
        `Input is treated as data, not instructions. If this is legitimate content, ` +
        `remove or rephrase the flagged patterns.`
    );
  }
}
