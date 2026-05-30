import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "../../api/client";
import { cancelJob, getExchanges, getJob, getProviders, getTaskTypes, startJob } from "../../api/plans";
import { getLatestScan } from "../../api/scans";
import { getRecordings } from "../../api/stats";
import type {
  Exchange,
  ExchangeTaskStatus,
  JobStatus,
  PentestItemInput,
  RecordingInfo,
  ScanResultRecord,
  TerminationResult,
  VulnerabilityCheck,
} from "../../api/types";
import { useFetch } from "../../lib/useFetch";
import { usePersistedState } from "../../lib/usePersistedState";
import { usePolling } from "../../lib/usePolling";
import { useAnalysisQueue } from "../../state/AnalysisQueueContext";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { RecordingSelector } from "../common/RecordingSelector";
import { ExchangeList } from "./ExchangeList";
import { LaunchControl } from "./LaunchControl";
import {
  reconcilePlanConfig,
  TEST_PLANNER_CONFIG_KEY,
  TEST_PLANNER_JOB_KEY,
} from "./persistedConfig";
import type { ActiveJobRef } from "./persistedConfig";
import { ProviderForm } from "./ProviderForm";
import { ScanHistorySelector } from "./ScanHistorySelector";
import type { EditableExchange, PlanConfig } from "./types";
import { customAnalysisCheck, seedPlanConfig, toExchange } from "./types";

const DEFAULT_RECORDING_ID = 1;
const POLL_INTERVAL_MS = 1500;

/** Flatten a completed analysis job into one pentest item per suggested check.
 *  Item ids (`${exchange_id}#${idx}`) double as the per-check selection keys. */
function buildPentestItems(
  job: JobStatus | null,
  exchanges: EditableExchange[],
): PentestItemInput[] {
  if (!job || job.status !== "done") return [];
  const exchangeById = new Map(exchanges.map((it) => [it.id, toExchange(it)]));
  const items: PentestItemInput[] = [];
  for (const task of job.tasks) {
    if (task.status !== "done" || !task.result) continue;
    const exchange = exchangeById.get(task.exchange_id);
    if (!exchange) continue;
    const checks = (task.result.payload.checks as VulnerabilityCheck[] | undefined) ?? [];
    checks.forEach((check, idx) => {
      items.push({ id: `${task.exchange_id}#${idx}`, exchange, check });
    });
  }
  return items;
}

export function CreatePlanTab() {
  const recordings = useFetch<RecordingInfo[]>(() => getRecordings(), []);
  const providers = useFetch(() => getProviders(), []);
  const taskTypes = useFetch(() => getTaskTypes(), []);
  const { enqueue } = useAnalysisQueue();

  // Hydrate the live job handle and LLM configuration from the browser so they
  // survive refreshes/restarts (both hydrate synchronously on first render).
  const [jobRef, setJobRef, { clear: clearStoredJobRef }] =
    usePersistedState<ActiveJobRef>(TEST_PLANNER_JOB_KEY);
  // Land back on the recording an analysis was launched for, so its progress is
  // visible immediately after a refresh.
  const [recordingId, setRecordingId] = useState(jobRef?.recordingId ?? DEFAULT_RECORDING_ID);
  const exchanges = useFetch(() => getExchanges(recordingId), [recordingId]);

  const [items, setItems] = useState<EditableExchange[]>([]);
  const [config, setConfig, { clear: clearStoredConfig }] =
    usePersistedState<PlanConfig>(TEST_PLANNER_CONFIG_KEY);
  const configReconciled = useRef(false);
  const [loaded, setLoaded] = useState<ScanResultRecord | null>(null);

  // Drop the persisted live job handle (e.g. the user picked a stored scan, or
  // the backend restarted and the job is gone) and stop polling for it.
  const clearJobRef = useCallback(() => {
    clearStoredJobRef();
    setJobRef(null);
  }, [clearStoredJobRef, setJobRef]);

  // The live job only applies while the current recording + task type match the
  // handle it was launched for; otherwise we show that view's stored scan.
  const activeJobId =
    jobRef && jobRef.recordingId === recordingId && jobRef.taskType === config?.taskType
      ? jobRef.jobId
      : null;
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [terminating, setTerminating] = useState(false);
  const [termination, setTermination] = useState<TerminationResult | null>(null);
  const [terminationError, setTerminationError] = useState<string | null>(null);
  // Per-check selection (keyed by pentest item id) and a transient queue note.
  const [selectedCheckIds, setSelectedCheckIds] = useState<Set<string>>(new Set());
  const [queuedNote, setQueuedNote] = useState<string | null>(null);

  // Seed the config once the providers and task types have loaded.
  useEffect(() => {
    if (config || !providers.data || !taskTypes.data) return;
    const provider = providers.data.providers[0];
    const task = taskTypes.data.tasks[0];
    if (!provider || !task) return;
    setConfig(seedPlanConfig(provider, task));
  }, [config, providers.data, taskTypes.data, setConfig]);

  // Once the catalogues are known, reconcile a restored config against them
  // (drop a provider/task that's gone, refresh prompt parts). Runs once; when
  // not hydrated `config` is still null here, so this is a no-op and the seed
  // effect above produces an already-valid config.
  useEffect(() => {
    if (!providers.data || !taskTypes.data || configReconciled.current) return;
    configReconciled.current = true;
    const list = providers.data.providers;
    const tasks = taskTypes.data.tasks;
    setConfig((prev) => (prev ? reconcilePlanConfig(prev, list, tasks) : prev));
  }, [providers.data, taskTypes.data, setConfig]);

  // Drop the saved config and rebuild it from the first provider + task type,
  // exactly as a fresh first visit would.
  const resetConfig = useCallback(() => {
    clearStoredConfig();
    const provider = providers.data?.providers[0];
    const task = taskTypes.data?.tasks[0];
    setConfig(provider && task ? seedPlanConfig(provider, task) : null);
    configReconciled.current = true;
  }, [providers.data, taskTypes.data, clearStoredConfig, setConfig]);

  // Re-seed the selection when the exchange list (re)loads. The live job is not
  // cleared here: it's scoped to its recording via `activeJobId`, so it stays
  // hidden for other recordings yet reappears (and keeps polling) on return —
  // including right after a refresh, where this effect also runs on mount.
  useEffect(() => {
    if (!exchanges.data) return;
    setItems(exchanges.data.items.map((exchange) => ({ ...exchange, selected: true })));
    setTermination(null);
    setTerminationError(null);
    setQueuedNote(null);
  }, [exchanges.data]);

  // Load the last stored scan for this recording + task type so the suggestions
  // reappear after a reload. A live job (below) takes precedence when present.
  useEffect(() => {
    const taskType = config?.taskType;
    if (!taskType) return;
    let cancelled = false;
    setLoaded(null);
    getLatestScan(recordingId, taskType)
      .then((record) => {
        if (!cancelled && record) setLoaded(record);
      })
      .catch(() => {
        /* best-effort: show nothing if the stored scan can't be loaded */
      });
    return () => {
      cancelled = true;
    };
  }, [recordingId, config?.taskType]);

  const job = usePolling<JobStatus>(
    () => getJob(activeJobId as string),
    {
      enabled: activeJobId !== null,
      intervalMs: POLL_INTERVAL_MS,
      stopWhen: (j) => j.status !== "running",
      // The job is gone (backend restarted): forget the handle so polling stops
      // and the view falls back to the last saved scan loaded below.
      onError: (err) => {
        if (err instanceof ApiError && err.status === 404) clearJobRef();
      },
    },
    [activeJobId],
  );

  // While a job is live its polled status wins; otherwise display the stored
  // snapshot (auto-loaded latest, or one picked from the history dropdown).
  const liveJob = activeJobId ? job.data : null;
  const effectiveJob: JobStatus | null = liveJob ?? (loaded?.payload as JobStatus | undefined) ?? null;
  const selectedScanId = liveJob ? null : loaded?.scan_result_id ?? null;

  const taskByExchange = useMemo(() => {
    const map = new Map<string, ExchangeTaskStatus>();
    effectiveJob?.tasks.forEach((task) => map.set(task.exchange_id, task));
    return map;
  }, [effectiveJob]);

  // One queueable analysis per suggested check, derived from the completed job.
  const pentestItems = useMemo(() => buildPentestItems(effectiveJob, items), [effectiveJob, items]);

  // Default to "all checked" whenever the set of suggested checks changes
  // (a job completes, the recording changes, or a stored scan is loaded).
  const checkIdsKey = pentestItems.map((it) => it.id).join("|");
  useEffect(() => {
    setSelectedCheckIds(new Set(checkIdsKey ? checkIdsKey.split("|") : []));
  }, [checkIdsKey]);

  const selectedCount = items.filter((item) => item.selected).length;
  const selectedCheckCount = pentestItems.filter((it) => selectedCheckIds.has(it.id)).length;
  const running = liveJob?.status === "running";

  // Switch the view to a stored snapshot chosen from the history dropdown.
  function showStoredScan(record: ScanResultRecord) {
    clearJobRef();
    setTermination(null);
    setTerminationError(null);
    setLoaded(record);
  }

  function toggle(id: string) {
    setItems((prev) =>
      prev.map((item) => (item.id === id ? { ...item, selected: !item.selected } : item)),
    );
  }

  function edit(id: string, patch: Partial<Exchange>) {
    setItems((prev) => prev.map((item) => (item.id === id ? { ...item, ...patch } : item)));
  }

  function setAllSelected(selected: boolean) {
    setItems((prev) => prev.map((item) => ({ ...item, selected })));
  }

  function toggleCheck(checkId: string) {
    setSelectedCheckIds((prev) => {
      const next = new Set(prev);
      if (next.has(checkId)) next.delete(checkId);
      else next.add(checkId);
      return next;
    });
  }

  function queueItems(toQueue: PentestItemInput[], note: string) {
    if (toQueue.length === 0) return;
    enqueue(toQueue.map((item) => ({ recordingId, label: `Recording ${recordingId}`, item })));
    setQueuedNote(note);
  }

  function queueSelected() {
    const selected = pentestItems.filter((it) => selectedCheckIds.has(it.id));
    queueItems(selected, `Queued ${selected.length} analysis task(s) to the Analysis Queue.`);
  }

  function queueAll() {
    queueItems(pentestItems, `Queued ${pentestItems.length} analysis task(s) to the Analysis Queue.`);
  }

  function queueCustom(exchangeId: string, description: string) {
    const source = items.find((it) => it.id === exchangeId);
    if (!source) return;
    enqueue([
      {
        recordingId,
        label: "Custom",
        item: {
          id: `custom#${exchangeId}#${Date.now()}`,
          exchange: toExchange(source),
          check: customAnalysisCheck(description),
        },
      },
    ]);
    setQueuedNote("Queued a custom analysis to the Analysis Queue.");
  }

  async function launch() {
    if (!config) return;
    const selected = items.filter((item) => item.selected).map(toExchange);
    setLaunchError(null);
    setTermination(null);
    setTerminationError(null);
    setLaunching(true);
    try {
      const response = await startJob({
        recording_id: recordingId,
        provider: config.provider,
        model: config.model || null,
        reasoning_effort: config.reasoningEffort || null,
        task_type: config.taskType,
        max_iterations: config.maxIterations,
        exchanges: selected,
        prompt_overrides: config.promptOverrides,
      });
      setJobRef({ jobId: response.job_id, recordingId, taskType: config.taskType });
    } catch (err) {
      setLaunchError(err instanceof Error ? err.message : String(err));
    } finally {
      setLaunching(false);
    }
  }

  async function terminate() {
    if (!activeJobId) return;
    setTerminationError(null);
    setTerminating(true);
    try {
      setTermination(await cancelJob(activeJobId));
    } catch (err) {
      setTerminationError(err instanceof Error ? err.message : String(err));
    } finally {
      setTerminating(false);
    }
  }

  return (
    <div className="create-plan">
      <div className="create-plan__bar">
        <RecordingSelector recordings={recordings.data} value={recordingId} onChange={setRecordingId} />
        {config && (
          <ScanHistorySelector
            recordingId={recordingId}
            scanType={config.taskType}
            selectedId={selectedScanId}
            refreshToken={`${recordingId}:${liveJob?.status ?? ""}`}
            disabled={running || launching}
            onSelect={showStoredScan}
            onDelete={setLoaded}
          />
        )}
      </div>
      {!liveJob && loaded && (
        <p className="muted">
          Showing saved scan from {new Date(loaded.created_at).toLocaleString()}.
        </p>
      )}

      <section className="panel">
        <div className="panel__title config-head">
          <span>LLM configuration</span>
          <button
            type="button"
            className="config-reset"
            disabled={!config || running || launching}
            onClick={resetConfig}
          >
            Reset to defaults
          </button>
        </div>
        {providers.error && <ErrorBanner message={providers.error} />}
        {taskTypes.error && <ErrorBanner message={taskTypes.error} />}
        {config && providers.data && taskTypes.data && (
          <ProviderForm
            providers={providers.data.providers}
            tasks={taskTypes.data.tasks}
            value={config}
            onChange={setConfig}
            disabled={running || launching}
          />
        )}
        <LaunchControl
          selectedCount={selectedCount}
          job={effectiveJob}
          launching={launching}
          error={launchError}
          onLaunch={launch}
          onTerminate={terminate}
          terminating={terminating}
          termination={termination}
          terminationError={terminationError}
        />
      </section>

      <section className="panel">
        <div className="panel__title create-plan__list-head">
          <span>Interesting data exchanges{exchanges.data ? ` (${items.length})` : ""}</span>
          {items.length > 0 && (
            <span className="create-plan__select-actions">
              <button type="button" onClick={() => setAllSelected(true)}>
                Select all
              </button>
              <button type="button" onClick={() => setAllSelected(false)}>
                Clear
              </button>
            </span>
          )}
        </div>
        {pentestItems.length > 0 && (
          <div className="create-plan__queue-bar">
            <span className="muted">
              {selectedCheckCount} of {pentestItems.length} suggested analyses selected
            </span>
            <span className="create-plan__queue-actions">
              <button
                type="button"
                className="launch__button"
                disabled={selectedCheckCount === 0}
                onClick={queueSelected}
              >
                Queue selected ({selectedCheckCount})
              </button>
              <button
                type="button"
                className="launch__button launch__button--secondary"
                onClick={queueAll}
              >
                Queue all
              </button>
            </span>
          </div>
        )}
        {queuedNote && <p className="create-plan__queue-note">{queuedNote}</p>}
        {exchanges.loading && <Loading label="Compiling exchanges..." />}
        {exchanges.error && <ErrorBanner message={exchanges.error} />}
        {exchanges.data && (
          <ExchangeList
            items={items}
            tasks={taskByExchange}
            onToggle={toggle}
            onEdit={edit}
            selectedCheckIds={selectedCheckIds}
            onToggleCheck={toggleCheck}
            onQueueCustom={queueCustom}
          />
        )}
        {job.error && <ErrorBanner message={job.error} />}
      </section>
    </div>
  );
}
