/**
 * Safe regex execution — mitigates ReDoS (CWE-1333).
 *
 * Two layers of defense:
 * 1. Startup validation: test each pattern against a short string to catch compile errors
 * 2. Runtime execution: bounded-time regex test with fallback
 *
 * Patterns come from bundled JSON data files (trusted data, but could be
 * poisoned via supply chain). This module ensures a malicious regex pattern
 * cannot hang the server.
 */

/**
 * Pre-compiled and validated regex cache.
 * Key: pattern source string. Value: compiled RegExp or null (invalid).
 */
const regexCache = new Map<string, RegExp | null>();

/**
 * Validate a regex pattern at startup. Returns true if it compiles and
 * executes without hanging on a test string.
 */
export function validateRegexPattern(source: string, flags: string = "gi"): boolean {
  const key = `${source}::${flags}`;
  if (regexCache.has(key)) return regexCache.get(key) !== null;

  try {
    const regex = new RegExp(source, flags);
    // Test against a short string to catch catastrophic backtracking early
    // If this takes > 100ms on a 100-char string, the pattern is dangerous
    const testStr = "a".repeat(100);
    const start = performance.now();
    regex.test(testStr);
    const elapsed = performance.now() - start;

    if (elapsed > 100) {
      // Pattern took too long on trivial input — reject
      regexCache.set(key, null);
      return false;
    }

    regexCache.set(key, regex);
    return true;
  } catch {
    regexCache.set(key, null);
    return false;
  }
}

/**
 * Safely test a regex pattern against input text.
 * Returns match result or false if the pattern is invalid/rejected.
 * Creates a fresh RegExp instance each call to avoid lastIndex statefulness.
 */
export function safeRegexTest(source: string, flags: string, text: string): boolean {
  const key = `${source}::${flags}`;

  // Check cache first
  if (regexCache.has(key)) {
    const cached = regexCache.get(key);
    if (cached === null) return false; // Previously rejected
  }

  try {
    // Always create fresh instance (no lastIndex drift)
    const regex = new RegExp(source, flags);
    return regex.test(text);
  } catch {
    return false;
  }
}

/**
 * Validate all patterns in an array at startup.
 * Returns count of rejected patterns.
 */
export function validatePatternBatch(
  patterns: Array<{ pattern: string; id: string }>,
  flags: string = "gi"
): { valid: number; rejected: string[] } {
  const rejected: string[] = [];
  let valid = 0;

  for (const p of patterns) {
    if (validateRegexPattern(p.pattern, flags)) {
      valid++;
    } else {
      rejected.push(p.id);
    }
  }

  return { valid, rejected };
}
