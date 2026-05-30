import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { cancelPentestJob, getMcpTools, getPentestJob, startPentestJob } from "../api/pentest";
import { getProviders } from "../api/plans";
import type {
  McpToolsetInfo,
  PentestItemInput,
  PentestItemStatus,
  PentestJobStatus,
  ProviderOption,
} from "../api/types";
import {
  buildToolConfig,
  defaultAllowedTools,
  seedPentestConfig,
} from "../components/attack/pentestConfig";
import {
  clearStoredConfig,
  loadStoredConfig,
  reconcileConfig,
  saveStoredConfig,
} from "../components/attack/persistedConfig";
import type { PentestUiConfig } from "../components/attack/types";
import { useFetch } from "../lib/useFetch";

const POLL_INTERVAL_MS = 1500;
/** Maximum investigations running at once when concurrent processing is enabled. */
const MAX_CONCURRENCY = 4;

/** Lifecycle of the queue processor. */
export type RunState = "idle" | "running" | "pausing";

/** A queued investigation: one pentest item plus its source context. */
export interface QueueEntry {
  /** Stable id for this queue entry (distinct from the pentest item id). */
  id: string;
  recordingId: number;
  /** Short source label, e.g. "Recording 1" or "Custom". */
  label: string;
  item: PentestItemInput;
}

/** A queue entry that has been submitted and is being investigated. */
export interface ActiveEntry extends QueueEntry {
  jobId: string;
  /** Latest polled status of the single-item job (null until first poll). */
  status: PentestJobStatus | null;
}

/** A finished investigation and its terminal item status. */
export interface CompletedEntry extends QueueEntry {
  result: PentestItemStatus;
}

interface AnalysisQueueValue {
  pending: QueueEntry[];
  active: ActiveEntry[];
  completed: CompletedEntry[];
  runState: RunState;
  config: PentestUiConfig | null;
  setConfig: (config: PentestUiConfig) => void;
  /** Discard the saved config and re-seed from provider/tool defaults. */
  resetConfig: () => void;
  /** Provider/tool catalogues for the config form (fetched once, shared). */
  providers: ProviderOption[] | undefined;
  providersError: string | null;
  toolsets: McpToolsetInfo[] | undefined;
  toolsLoading: boolean;
  toolsError: string | null;
  /** Append items to the pending queue. */
  enqueue: (items: Array<Omit<QueueEntry, "id">>) => void;
  /** Drop a not-yet-started entry from the pending queue. */
  evict: (id: string) => void;
  clearCompleted: () => void;
  /** Start processing the pending queue. */
  runAll: () => void;
  /** Stop picking up new items; in-flight investigations finish. */
  pauseAfterCurrent: () => void;
  /** Cancel all in-flight investigations now (and stop picking up new ones). */
  stopNow: () => void;
}

const AnalysisQueueContext = createContext<AnalysisQueueValue | null>(null);

let queueIdCounter = 0;
function nextQueueId(): string {
  queueIdCounter += 1;
  return `q${queueIdCounter}-${Date.now()}`;
}

/** Terminal item status used when a job returns no item or fails to start. */
function syntheticItem(entry: QueueEntry, error: string): PentestItemStatus {
  return {
    item_id: entry.item.id,
    title: entry.item.check.title,
    status: "error",
    result: null,
    error,
    iterations: null,
    stopped_on_limit: null,
    activity: null,
    pending_reviews: [],
  };
}

export function AnalysisQueueProvider({ children }: { children: ReactNode }) {
  const providers = useFetch(() => getProviders(), []);
  const tools = useFetch(() => getMcpTools(), []);

  const [pending, setPending] = useState<QueueEntry[]>([]);
  const [active, setActive] = useState<ActiveEntry[]>([]);
  const [completed, setCompleted] = useState<CompletedEntry[]>([]);
  const [runState, setRunState] = useState<RunState>("idle");
  // Hydrate from the browser so the configuration survives refreshes/restarts.
  const [config, setConfig] = useState<PentestUiConfig | null>(loadStoredConfig);
  // Skip the default-seeding effects below when we restored a saved config, so
  // they don't clobber the restored tool selection.
  const toolsSeeded = useRef(config !== null);
  const configReconciled = useRef(false);
  // True while a job submission is in flight, so the processor starts one at a time.
  const startingRef = useRef(false);
  // Mirror of `active` for the polling loop, so it always reads the current set.
  const activeRef = useRef<ActiveEntry[]>([]);
  useEffect(() => {
    activeRef.current = active;
  }, [active]);

  // Seed the config once providers load, then conservative tool defaults.
  useEffect(() => {
    if (config || !providers.data) return;
    const provider = providers.data.providers[0];
    if (!provider) return;
    setConfig(seedPentestConfig(provider));
  }, [config, providers.data]);

  useEffect(() => {
    if (!config || !tools.data || toolsSeeded.current) return;
    toolsSeeded.current = true;
    const defaults = defaultAllowedTools(tools.data.toolsets);
    setConfig((prev) => (prev ? { ...prev, allowedTools: defaults } : prev));
  }, [config, tools.data]);

  // Once the provider catalogue is known, reconcile a restored config against
  // it (drop a provider that's no longer available). Runs once; when not
  // hydrated `config` is still null here, so this is a no-op and the seed
  // effect above produces an already-valid config.
  useEffect(() => {
    if (!providers.data || configReconciled.current) return;
    configReconciled.current = true;
    const list = providers.data.providers;
    setConfig((prev) => (prev ? reconcileConfig(prev, list) : prev));
  }, [providers.data]);

  // Persist every config change (seed, reconcile, and user edits).
  useEffect(() => {
    if (config) saveStoredConfig(config);
  }, [config]);

  // Processor: while running and below capacity, submit the next pending entry.
  useEffect(() => {
    if (runState !== "running" || !config) return;
    if (startingRef.current) return;
    const maxActive = config.concurrent ? MAX_CONCURRENCY : 1;
    if (active.length >= maxActive || pending.length === 0) return;

    const next = pending[0];
    startingRef.current = true;
    // Remove from pending immediately so the entry is no longer evictable / re-picked.
    setPending((prev) => prev.filter((entry) => entry.id !== next.id));
    startPentestJob({
      recording_id: next.recordingId,
      provider: config.agent.provider,
      model: config.agent.model || null,
      reasoning_effort: config.agent.reasoningEffort || null,
      max_iterations: config.agent.maxIterations,
      items: [next.item],
      concurrent: false,
      tool_config: buildToolConfig(config),
      persist: false,
    })
      .then((response) => {
        setActive((prev) => [...prev, { ...next, jobId: response.job_id, status: null }]);
      })
      .catch((err) => {
        const message = err instanceof Error ? err.message : String(err);
        setCompleted((prev) => [{ ...next, result: syntheticItem(next, message) }, ...prev]);
      })
      .finally(() => {
        startingRef.current = false;
        // Nudge the processor to evaluate capacity again after the await settles.
        setActive((prev) => [...prev]);
      });
  }, [runState, config, active, pending]);

  // Settle the run state once the queue drains.
  useEffect(() => {
    if (active.length > 0 || startingRef.current) return;
    if (runState === "pausing") {
      setRunState("idle");
    } else if (runState === "running" && pending.length === 0) {
      setRunState("idle");
    }
  }, [active.length, pending.length, runState]);

  // Poll every in-flight job; move finished ones to the completed list.
  useEffect(() => {
    if (active.length === 0) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const run = async () => {
      const entries = activeRef.current;
      if (entries.length === 0) return;
      const settled = await Promise.all(
        entries.map((entry) =>
          getPentestJob(entry.jobId).then(
            (status) => ({ jobId: entry.jobId, status }),
            () => ({ jobId: entry.jobId, status: null as PentestJobStatus | null }),
          ),
        ),
      );
      if (cancelled) return;

      const statusByJob = new Map(settled.map((r) => [r.jobId, r.status]));
      const done: CompletedEntry[] = [];
      for (const entry of entries) {
        const status = statusByJob.get(entry.jobId);
        if (status && status.status !== "running") {
          const item = status.items[0] ?? syntheticItem(entry, "No result returned.");
          done.push({ ...entry, result: item });
        }
      }

      setActive((prev) =>
        prev.flatMap((entry) => {
          const status = statusByJob.get(entry.jobId);
          if (status === undefined) return [entry]; // added after this poll's snapshot
          if (status === null) return [entry]; // fetch failed; retry next tick
          if (status.status === "running") return [{ ...entry, status }];
          return []; // finished — moved to completed below
        }),
      );
      if (done.length > 0) setCompleted((prev) => [...done, ...prev]);

      if (!cancelled) timer = setTimeout(run, POLL_INTERVAL_MS);
    };

    void run();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [active.length]);

  const enqueue = useCallback((items: Array<Omit<QueueEntry, "id">>) => {
    if (items.length === 0) return;
    setPending((prev) => [...prev, ...items.map((item) => ({ ...item, id: nextQueueId() }))]);
  }, []);

  const evict = useCallback((id: string) => {
    setPending((prev) => prev.filter((entry) => entry.id !== id));
  }, []);

  const clearCompleted = useCallback(() => setCompleted([]), []);

  // Drop the saved config and rebuild it from provider + tool defaults, exactly
  // as a fresh first visit would. If tools haven't loaded yet, defer the tool
  // defaults to the seeding effect above.
  const resetConfig = useCallback(() => {
    clearStoredConfig();
    const provider = providers.data?.providers[0];
    if (!provider) {
      setConfig(null);
      toolsSeeded.current = false;
      return;
    }
    const seeded = seedPentestConfig(provider);
    const toolsReady = tools.data != null;
    setConfig({
      ...seeded,
      allowedTools: toolsReady ? defaultAllowedTools(tools.data!.toolsets) : [],
    });
    toolsSeeded.current = toolsReady;
    configReconciled.current = true;
  }, [providers.data, tools.data]);

  const runAll = useCallback(() => setRunState("running"), []);
  const pauseAfterCurrent = useCallback(() => setRunState("pausing"), []);

  const stopNow = useCallback(() => {
    setRunState("pausing");
    activeRef.current.forEach((entry) => {
      cancelPentestJob(entry.jobId).catch(() => {
        /* best-effort: the poll will still observe the terminal status */
      });
    });
  }, []);

  const value: AnalysisQueueValue = {
    pending,
    active,
    completed,
    runState,
    config,
    setConfig,
    resetConfig,
    providers: providers.data?.providers,
    providersError: providers.error,
    toolsets: tools.data?.toolsets,
    toolsLoading: tools.loading,
    toolsError: tools.error,
    enqueue,
    evict,
    clearCompleted,
    runAll,
    pauseAfterCurrent,
    stopNow,
  };

  return (
    <AnalysisQueueContext.Provider value={value}>{children}</AnalysisQueueContext.Provider>
  );
}

export function useAnalysisQueue(): AnalysisQueueValue {
  const value = useContext(AnalysisQueueContext);
  if (!value) {
    throw new Error("useAnalysisQueue must be used within an AnalysisQueueProvider");
  }
  return value;
}
