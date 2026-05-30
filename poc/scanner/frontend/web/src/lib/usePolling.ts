import { useEffect, useRef, useState } from "react";

export interface PollState<T> {
  data: T | null;
  error: string | null;
}

export interface PollOptions<T> {
  enabled: boolean;
  intervalMs: number;
  /** Stop polling once this returns true for the latest result. */
  stopWhen?: (data: T) => boolean;
  /** Called with the raw error on each failed poll, so callers can inspect its
   *  type (e.g. clear state on a 404). Polling still retries afterwards. */
  onError?: (err: unknown) => void;
}

/**
 * Poll an async function on an interval while `enabled`, re-running when `deps`
 * change. Uses a recursive timeout (no overlapping calls) and stops scheduling
 * once `stopWhen` is satisfied. Returns the latest result/error.
 */
export function usePolling<T>(
  fn: () => Promise<T>,
  { enabled, intervalMs, stopWhen, onError }: PollOptions<T>,
  deps: unknown[],
): PollState<T> {
  const [state, setState] = useState<PollState<T>>({ data: null, error: null });
  // Held in a ref so the polling effect always calls the latest callback
  // without listing it in `deps` (which the caller controls).
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  useEffect(() => {
    if (!enabled) {
      setState({ data: null, error: null });
      return;
    }
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = () => {
      fn()
        .then((data) => {
          if (!active) return;
          setState({ data, error: null });
          if (stopWhen && stopWhen(data)) return;
          timer = setTimeout(tick, intervalMs);
        })
        .catch((err: unknown) => {
          if (!active) return;
          onErrorRef.current?.(err);
          setState((prev) => ({
            ...prev,
            error: err instanceof Error ? err.message : String(err),
          }));
          timer = setTimeout(tick, intervalMs);
        });
    };
    tick();

    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}
