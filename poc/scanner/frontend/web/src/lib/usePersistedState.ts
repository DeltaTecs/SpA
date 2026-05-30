import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";

/** Read and parse an object value from localStorage, or null when absent/unreadable. */
function readStored<T extends object>(key: string): T | null {
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

export interface PersistedStateMeta {
  /** True when the initial value was restored from storage (vs. a fresh start). */
  hydrated: boolean;
  /** Remove the persisted value from storage (e.g. for "reset to defaults"). */
  clear: () => void;
}

/**
 * A `useState` whose value is mirrored to `localStorage` under `key`, surviving
 * refreshes and browser restarts. The value is JSON-serialized; a missing,
 * corrupt, or non-object payload is ignored (so bad data can't break boot, and
 * a future breaking change is rolled by bumping the version in `key`).
 *
 * Suited to UI configuration that starts `null` and is seeded asynchronously
 * once some catalogue loads: callers branch on `meta.hydrated` to skip seeding
 * a restored value, and call `meta.clear()` to discard it.
 */
export function usePersistedState<T extends object>(
  key: string,
): [T | null, Dispatch<SetStateAction<T | null>>, PersistedStateMeta] {
  const [value, setValue] = useState<T | null>(() => readStored<T>(key));
  // Captured once: whether the very first value came from storage.
  const hydrated = useRef(value !== null).current;

  useEffect(() => {
    if (value === null) return;
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* best-effort: storage full or unavailable */
    }
  }, [key, value]);

  const clear = useCallback(() => {
    try {
      localStorage.removeItem(key);
    } catch {
      /* best-effort */
    }
  }, [key]);

  return [value, setValue, { hydrated, clear }];
}
