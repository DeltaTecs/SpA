import { useEffect, useMemo, useState } from "react";
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
import { usePolling } from "../../lib/usePolling";
import { useAnalysisQueue } from "../../state/AnalysisQueueContext";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { RecordingSelector } from "../common/RecordingSelector";
import { ExchangeList } from "./ExchangeList";
import { LaunchControl } from "./LaunchControl";
import { ProviderForm } from "./ProviderForm";
import { ScanHistorySelector } from "./ScanHistorySelector";
import type { EditableExchange, PlanConfig } from "./types";
import { customAnalysisCheck, taskPromptDefaults, toExchange } from "./types";

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

  const [recordingId, setRecordingId] = useState(DEFAULT_RECORDING_ID);
  const exchanges = useFetch(() => getExchanges(recordingId), [recordingId]);

  const [items, setItems] = useState<EditableExchange[]>([]);
  const [config, setConfig] = useState<PlanConfig | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<ScanResultRecord | null>(null);
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
    setConfig({
      provider: provider.type,
      model: provider.default_model ?? "",
      reasoningEffort: "",
      taskType: task.task_type,
      maxIterations: 10,
      promptOverrides: taskPromptDefaults(task),
    });
  }, [config, providers.data, taskTypes.data]);

  // Re-seed the selection when the exchange list (re)loads; drop any old job.
  useEffect(() => {
    if (!exchanges.data) return;
    setItems(exchanges.data.items.map((exchange) => ({ ...exchange, selected: true })));
    setJobId(null);
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
    () => getJob(jobId as string),
    { enabled: jobId !== null, intervalMs: POLL_INTERVAL_MS, stopWhen: (j) => j.status !== "running" },
    [jobId],
  );

  // While a job is live its polled status wins; otherwise display the stored
  // snapshot (auto-loaded latest, or one picked from the history dropdown).
  const liveJob = jobId ? job.data : null;
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
    setJobId(null);
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
      setJobId(response.job_id);
    } catch (err) {
      setLaunchError(err instanceof Error ? err.message : String(err));
    } finally {
      setLaunching(false);
    }
  }

  async function terminate() {
    if (!jobId) return;
    setTerminationError(null);
    setTerminating(true);
    try {
      setTermination(await cancelJob(jobId));
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
        <h2 className="panel__title">LLM configuration</h2>
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
