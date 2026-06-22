// Small best-effort wrappers around localStorage for JSON-serialized state.
// All operations swallow failures (storage disabled/full, corrupt payloads) so
// that a missing or broken value can never break boot — callers treat a failed
// read as "nothing stored". A breaking change to a stored shape is rolled by
// bumping the version suffix in the key (see persistedConfig.ts).

/** Read and JSON-parse an object value from `key`, or null when absent/unreadable. */
export function readJson<T extends object>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as T;
  } catch {
    return null;
  }
}

/** JSON-serialize `value` and write it to `key`; a no-op if storage is unavailable. */
export function writeJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* best-effort: storage full or unavailable */
  }
}

/** Remove `key` from storage; a no-op if storage is unavailable. */
export function removeStored(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    /* best-effort */
  }
}
