import { useNavigate } from "react-router-dom";
import type {
  ExploitFinding,
  ExploitItemInput,
  PentestReportPayload,
  TaskResult,
} from "../api/types";
import { LlmProviderFields } from "../components/attack/LlmProviderFields";
import { McpToolConfig } from "../components/attack/McpToolConfig";
import { ReportCard } from "../components/attack/ReportCard";
import { ReviewPanel, type ReviewEntry } from "../components/attack/ReviewPanel";
import { SavedReportsPanel } from "../components/attack/SavedReportsPanel";
import { PENTEST_SCAN_TYPE } from "../api/scans";
import {
  describeCompletedEntry,
  describeTarget,
  exportCompletedToText,
} from "../components/attack/describeResult";
import { openToolScript } from "../components/toolscript/openToolScript";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { Loading } from "../components/common/Loading";
import {
  type ActiveEntry,
  type CompletedEntry,
  type QueueEntry,
  useAnalysisQueue,
} from "../state/AnalysisQueueContext";
import { useExploitQueue } from "../state/ExploitQueueContext";
import { useGuidedAnalysis } from "../state/GuidedAnalysisContext";

/** A descriptive target line (full HTTP URL incl. domain, plus ip:port). */
function entryTarget(entry: QueueEntry): string {
  return describeTarget(entry.item.exchange);
}

/** Read the verdict/summary/evidence of a completed `pentest` analysis into the
 *  exploit finding the Exploit Queue starts from (empty when not a pentest result). */
function pentestFinding(result: TaskResult | null): ExploitFinding {
  if (!result || result.task_type !== "pentest") {
    return { verdict: "", summary: "", evidence: [] };
  }
  const payload = result.payload as unknown as PentestReportPayload;
  return {
    verdict: payload.verdict ?? "",
    summary: payload.summary ?? "",
    evidence: payload.evidence ?? [],
  };
}

/** Download `text` as a file the browser saves to the user's downloads. */
function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
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
    removeCompleted,
    clearCompleted,
    runAll,
    pauseAfterCurrent,
    stopNow,
  } = useAnalysisQueue();
  const { stageInput } = useGuidedAnalysis();
  const { enqueue: enqueueExploit } = useExploitQueue();
  const navigate = useNavigate();

  const configDisabled = runState !== "idle";
  const canRun = !!config && pending.length > 0 && runState !== "running";

  // Push a result's description into the Guided Analysis chat, then switch tabs.
  function sendToGuided(entry: CompletedEntry) {
    stageInput(describeCompletedEntry(entry));
    navigate("/guided-analysis");
  }

  // Queue a completed analysis for exploitation, carrying its finding, then switch tabs.
  function sendToExploit(entry: CompletedEntry) {
    const item: ExploitItemInput = {
      id: entry.item.id,
      exchange: entry.item.exchange,
      check: entry.item.check,
      finding: pentestFinding(entry.result.result),
    };
    enqueueExploit([{ recordingId: entry.recordingId, label: entry.label, item }]);
    navigate("/exploit-queue");
  }

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
              <div className="analysis-queue__completed-actions">
                <button
                  type="button"
                  onClick={() =>
                    downloadText("analysis-results.txt", exportCompletedToText(completed))
                  }
                >
                  Export all
                </button>
                <button type="button" onClick={clearCompleted}>
                  Clear
                </button>
              </div>
            )}
          </div>
          {completed.length === 0 && <div className="muted">No completed analyses yet.</div>}
          {completed.map((entry) => (
            <div key={entry.id} className="analysis-queue__completed-item">
              <p className="muted analysis-queue__context">
                {entry.label} · {entryTarget(entry)}
              </p>
              <ReportCard item={entry.result} />
              <div className="analysis-queue__result-actions">
                {entry.jobId && (
                  <button
                    type="button"
                    onClick={() =>
                      openToolScript({
                        source: "pentest",
                        jobId: entry.jobId!,
                        itemId: entry.item.id,
                      })
                    }
                  >
                    Tool script
                  </button>
                )}
                <button type="button" onClick={() => sendToGuided(entry)}>
                  Send to Guided Analysis
                </button>
                <button type="button" onClick={() => sendToExploit(entry)}>
                  Send to Exploit Queue
                </button>
                <button
                  type="button"
                  className="analysis-queue__result-delete"
                  onClick={() => removeCompleted(entry.id)}
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </section>
      </div>

      <SavedReportsPanel scanType={PENTEST_SCAN_TYPE} refreshToken={completed.length} />
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
