// Formatting helpers for the Tool Transcript page, so transcripts read as
// documents rather than raw JSON blobs.

type RenderSource = "arguments" | "output";

export interface ValueContext {
  key?: string;
  source: RenderSource;
  toolName?: string | null;
  rootArguments?: Record<string, unknown>;
}

const PYTHON_CODE_KEYS = new Set([
  "script",
  "code",
  "source",
  "sourcecode",
  "pythoncode",
  "content",
  "filecontent",
]);

const PYTHON_WRITING_TOOLS = new Set(["create_file", "modify_file", "write_file"]);

const PATH_KEYS = new Set([
  "path",
  "filepath",
  "file",
  "filename",
  "target",
  "targetpath",
  "destination",
  "destinationpath",
]);

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

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function childContext(parent: ValueContext, key: string): ValueContext {
  return {
    ...parent,
    key,
  };
}

export function shouldRenderPythonCode(value: string, context: ValueContext): boolean {
  const key = normalizedKey(context.key);
  const toolName = context.toolName ?? "";

  if (toolName === "execute_python_script") {
    return PYTHON_CODE_KEYS.has(key) || looksLikePython(value);
  }

  if (
    PYTHON_WRITING_TOOLS.has(toolName) &&
    PYTHON_CODE_KEYS.has(key) &&
    hasPythonPathArgument(context.rootArguments)
  ) {
    return true;
  }

  if (!PYTHON_CODE_KEYS.has(key)) {
    return false;
  }

  return looksLikePython(value);
}

export function containsPythonCode(value: unknown, context: ValueContext): boolean {
  if (typeof value === "string") {
    return shouldRenderPythonCode(value, context);
  }
  if (Array.isArray(value)) {
    return value.some((item, index) => containsPythonCode(item, childContext(context, String(index))));
  }
  if (isPlainObject(value)) {
    return Object.entries(value).some(([key, item]) =>
      containsPythonCode(item, childContext(context, key)),
    );
  }
  return false;
}

function normalizedKey(key: string | undefined): string {
  return (key ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function hasPythonPathArgument(args: Record<string, unknown> | undefined): boolean {
  if (!args) return false;
  return Object.entries(args).some(([key, value]) => {
    if (!PATH_KEYS.has(normalizedKey(key)) || typeof value !== "string") {
      return false;
    }
    return isPythonPath(value);
  });
}

function isPythonPath(path: string): boolean {
  return /\.(py|pyw)$/i.test(path.trim());
}

function looksLikePython(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  return [
    /^\s*(async\s+def|def|class)\s+\w+/m,
    /^\s*(from\s+\S+\s+import|import\s+\S+)/m,
    /^\s*if\s+__name__\s*==\s*["']__main__["']\s*:/m,
    /^\s*(for|while|if|elif|else|try|except|with)\b.*:\s*$/m,
    /^\s*print\s*\(/m,
    /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+/m,
  ].some((pattern) => pattern.test(value));
}
