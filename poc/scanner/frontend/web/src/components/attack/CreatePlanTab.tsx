import { useEffect, useMemo, useState } from "react";
import { cancelJob, getExchanges, getJob, getProviders, getTaskTypes, startJob } from "../../api/plans";
import { getRecordings } from "../../api/stats";
import type {
  Exchange,
  ExchangeTaskStatus,
  JobStatus,
  PentestItemInput,
  RecordingInfo,
  TerminationResult,
  VulnerabilityCheck,
} from "../../api/types";
import { useFetch } from "../../lib/useFetch";
import { usePolling } from "../../lib/usePolling";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { RecordingSelector } from "../common/RecordingSelector";
import { ExchangeList } from "./ExchangeList";
import { LaunchControl } from "./LaunchControl";
import { ProviderForm } from "./ProviderForm";
import type { EditableExchange, PentestPlan, PlanConfig } from "./types";
import { taskPromptDefaults, toExchange } from "./types";

const DEFAULT_RECORDING_ID = 1;
const POLL_INTERVAL_MS = 1500;

interface CreatePlanTabProps {
  /** Called with the executable plan once an analysis completes (or null while none). */
  onPlanReady: (plan: PentestPlan | null) => void;
  /** Whether the Pentest tab is currently reachable (a plan exists). */
  pentestReady: boolean;
  /** Navigate to the Pentest tab. */
  onGoToPentest: () => void;
}

/** Flatten a completed analysis job into one pentest item per suggested check. */
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

export function CreatePlanTab({ onPlanReady, pentestReady, onGoToPentest }: CreatePlanTabProps) {
  const recordings = useFetch<RecordingInfo[]>(() => getRecordings(), []);
  const providers = useFetch(() => getProviders(), []);
  const taskTypes = useFetch(() => getTaskTypes(), []);

  const [recordingId, setRecordingId] = useState(DEFAULT_RECORDING_ID);
  const exchanges = useFetch(() => getExchanges(recordingId), [recordingId]);

  const [items, setItems] = useState<EditableExchange[]>([]);
  const [config, setConfig] = useState<PlanConfig | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [terminating, setTerminating] = useState(false);
  const [termination, setTermination] = useState<TerminationResult | null>(null);
  const [terminationError, setTerminationError] = useState<string | null>(null);

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
  }, [exchanges.data]);

  const job = usePolling<JobStatus>(
    () => getJob(jobId as string),
    { enabled: jobId !== null, intervalMs: POLL_INTERVAL_MS, stopWhen: (j) => j.status !== "running" },
    [jobId],
  );

  const taskByExchange = useMemo(() => {
    const map = new Map<string, ExchangeTaskStatus>();
    job.data?.tasks.forEach((task) => map.set(task.exchange_id, task));
    return map;
  }, [job.data]);

  // Lift the executable plan (one item per suggested check) up to the Attack page
  // so the Pentest tab can be enabled and seeded once the analysis completes.
  const pentestItems = useMemo(() => buildPentestItems(job.data, items), [job.data, items]);
  useEffect(() => {
    onPlanReady(pentestItems.length > 0 ? { recordingId, items: pentestItems } : null);
  }, [pentestItems, recordingId, onPlanReady]);

  const selectedCount = items.filter((item) => item.selected).length;
  const running = job.data?.status === "running";
  const planReady = pentestItems.length > 0;

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
      </div>

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
          job={job.data}
          launching={launching}
          error={launchError}
          onLaunch={launch}
          planReady={planReady}
          pentestReady={pentestReady}
          onGoToPentest={onGoToPentest}
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
        {exchanges.loading && <Loading label="Compiling exchanges..." />}
        {exchanges.error && <ErrorBanner message={exchanges.error} />}
        {exchanges.data && (
          <ExchangeList items={items} tasks={taskByExchange} onToggle={toggle} onEdit={edit} />
        )}
        {job.error && <ErrorBanner message={job.error} />}
      </section>
    </div>
  );
}
