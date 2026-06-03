// Formatting helpers for the Tool-script page, so transcripts read as documents
// rather than raw JSON blobs.

/**
 * Parse `text` as a JSON object/array, or return `undefined` when it isn't one.
 * Only braces/brackets are treated as JSON so plain prose (which may legitimately
 * start with a quote or number) is left as text.
 */
export function tryParseJson(text: string): unknown {
  const trimmed = text.trim();
  if (!trimmed) return undefined;
  const first = trimmed[0];
  if (first !== "{" && first !== "[") return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

/** Indented JSON for objects/arrays; the indentation itself supplies line breaks. */
export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

/** Whether an argument value is a scalar that reads fine inline. */
export function isScalar(value: unknown): value is string | number | boolean | null {
  return value === null || ["string", "number", "boolean"].includes(typeof value);
}

/** Render a scalar argument value as a short inline string. */
export function scalarText(value: string | number | boolean | null): string {
  return value === null ? "null" : String(value);
}
