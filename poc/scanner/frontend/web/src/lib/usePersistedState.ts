import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { readJson, removeStored, writeJson } from "./storage";

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
  const [value, setValue] = useState<T | null>(() => readJson<T>(key));
  // Captured once: whether the very first value came from storage.
  const hydrated = useRef(value !== null).current;

  useEffect(() => {
    if (value === null) return;
    writeJson(key, value);
  }, [key, value]);

  const clear = useCallback(() => removeStored(key), [key]);

  return [value, setValue, { hydrated, clear }];
}
