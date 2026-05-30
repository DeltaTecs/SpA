/**
 * Helpers for rendering a tool call's arguments in the review UI.
 *
 * The arguments arrive as an already-parsed object. Pretty-printing the whole
 * object with `JSON.stringify` escapes the real newlines inside string values
 * (e.g. a multi-line shell command) into literal `\n`, which is unreadable.
 * `describeToolArguments` classifies each entry so the UI can show string values
 * verbatim (real line breaks preserved) and only fall back to JSON for nested
 * structures.
 */

export type ToolArgField =
  | { key: string; kind: "text"; value: string; multiline: boolean }
  | { key: string; kind: "json"; value: string };

export function describeToolArguments(args: Record<string, unknown>): ToolArgField[] {
  return Object.entries(args).map(([key, raw]) => {
    if (typeof raw === "string") {
      return { key, kind: "text", value: raw, multiline: raw.includes("\n") };
    }
    if (raw === null || typeof raw === "number" || typeof raw === "boolean") {
      return { key, kind: "text", value: String(raw), multiline: false };
    }
    // Objects and arrays: keep structure visible via pretty JSON.
    return { key, kind: "json", value: formatToolArgumentsRaw(raw) };
  });
}

export function formatToolArgumentsRaw(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
