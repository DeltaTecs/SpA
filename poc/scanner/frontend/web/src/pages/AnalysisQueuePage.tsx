import { LlmProviderFields } from "../components/attack/LlmProviderFields";
import { McpToolConfig } from "../components/attack/McpToolConfig";
import { ReportCard } from "../components/attack/ReportCard";
import { ReviewPanel, type ReviewEntry } from "../components/attack/ReviewPanel";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { Loading } from "../components/common/Loading";
import {
  type ActiveEntry,
  type QueueEntry,
  useAnalysisQueue,
} from "../state/AnalysisQueueContext";

function entryTarget(entry: QueueEntry): string {
  const remote = entry.item.exchange.remote;
  if (remote) return `${remote.ip ?? "?"}:${remote.port ?? "?"}`;
  return "recorded endpoint";
}

export function AnalysisQueuePage() {
  const {
    pending,
    active,
    completed,
    runState,
    config,
    setConfig,
    resetConfig,
    providers,
    providersError,
    toolsets,
    toolsLoading,
    toolsError,
    evict,
    clearCompleted,
    runAll,
    pauseAfterCurrent,
    stopNow,
  } = useAnalysisQueue();

  const configDisabled = runState !== "idle";
  const canRun = !!config && pending.length > 0 && runState !== "running";

  return (
    <div className="page">
      <header className="page__header">
        <h1>Analysis Queue</h1>
      </header>

      <section className="panel">
        <div className="panel__title config-head">
          <span>Investigation configuration</span>
          <button
            type="button"
            className="config-reset"
            disabled={configDisabled || !config}
            onClick={resetConfig}
          >
            Reset to defaults
          </button>
        </div>
        {providersError && <ErrorBanner message={providersError} />}
        {config && providers && (
          <div className="provider-form">
            <LlmProviderFields
              providers={providers}
              value={config.agent}
              onChange={(agent) => setConfig({ ...config, agent })}
              disabled={configDisabled}
            />
          </div>
        )}
        {config && providers && (
          <McpToolConfig
            value={config}
            onChange={setConfig}
            toolsets={toolsets}
            toolsLoading={toolsLoading}
            toolsError={toolsError}
            providers={providers}
            disabled={configDisabled}
          />
        )}

        <label className="tool-config__check">
          <input
            type="checkbox"
            disabled={!config}
            checked={config?.concurrent ?? false}
            onChange={(e) => config && setConfig({ ...config, concurrent: e.target.checked })}
          />
          <span>Run multiple queue elements concurrently</span>
        </label>

        <div className="launch">
          <button type="button" className="launch__button" disabled={!canRun} onClick={runAll}>
            {runState === "running" ? "Running…" : "Run All Queued Pentests"}
          </button>
          {runState === "running" && (
            <button
              type="button"
              className="launch__button launch__button--secondary"
              onClick={pauseAfterCurrent}
            >
              Pause after current test
            </button>
          )}
          {runState === "pausing" && <span className="muted">Pausing after current test…</span>}
          {active.length > 0 && (
            <button type="button" className="launch__button launch__button--danger" onClick={stopNow}>
              Stop now
            </button>
          )}
        </div>
      </section>

      {active.map((entry) => {
        const entries = reviewEntries(entry);
        if (entries.length === 0) return null;
        return <ReviewPanel key={entry.jobId} jobId={entry.jobId} entries={entries} />;
      })}

      <div className="analysis-queue">
        <section className="panel analysis-queue__col">
          <h2 className="panel__title">
            Queue <span className="analysis-queue__count">{active.length + pending.length}</span>
          </h2>
          {active.length === 0 && pending.length === 0 && (
            <div className="muted">
              Nothing queued. Add analyses from the Test Planner, then press “Run All Queued
              Pentests”.
            </div>
          )}
          {active.map((entry) => (
            <ActiveCard key={entry.id} entry={entry} />
          ))}
          {pending.map((entry) => (
            <PendingCard key={entry.id} entry={entry} onEvict={() => evict(entry.id)} />
          ))}
        </section>

        <section className="panel analysis-queue__col">
          <div className="panel__title analysis-queue__completed-head">
            <span>
              Completed <span className="analysis-queue__count">{completed.length}</span>
            </span>
            {completed.length > 0 && (
              <button type="button" onClick={clearCompleted}>
                Clear
              </button>
            )}
          </div>
          {completed.length === 0 && <div className="muted">No completed analyses yet.</div>}
          {completed.map((entry) => (
            <div key={entry.id} className="analysis-queue__completed-item">
              <p className="muted analysis-queue__context">
                {entry.label} · {entryTarget(entry)}
              </p>
              <ReportCard item={entry.result} />
            </div>
          ))}
        </section>
      </div>
    </div>
  );
}

function reviewEntries(entry: ActiveEntry): ReviewEntry[] {
  if (!entry.status) return [];
  return entry.status.items.flatMap((item) =>
    item.pending_reviews.map((review) => ({ review, itemTitle: item.title })),
  );
}

function ActiveCard({ entry }: { entry: ActiveEntry }) {
  const item = entry.status?.items[0];
  const status = item?.status ?? "running";
  return (
    <article className="queue-card queue-card--active">
      <header className="queue-card__head">
        <span className={`task-status task-status--${status}`}>{status}</span>
        <span className="queue-card__title">{entry.item.check.title}</span>
      </header>
      <p className="muted analysis-queue__context">
        {entry.label} · {entryTarget(entry)}
      </p>
      <Loading label={item?.activity ?? "Investigating…"} />
    </article>
  );
}

function PendingCard({ entry, onEvict }: { entry: QueueEntry; onEvict: () => void }) {
  return (
    <article className="queue-card">
      <header className="queue-card__head">
        <span className="task-status task-status--pending">queued</span>
        <span className="queue-card__title">{entry.item.check.title}</span>
        <button type="button" className="queue-card__evict" onClick={onEvict}>
          Evict
        </button>
      </header>
      <p className="muted analysis-queue__context">
        {entry.label} · {entryTarget(entry)}
      </p>
    </article>
  );
}
