import type { JobStatus, TaskStatusValue, TerminationResult } from "../../api/types";
import { TerminateControl } from "./TerminateControl";

interface LaunchControlProps {
  selectedCount: number;
  job: JobStatus | null;
  launching: boolean;
  error: string | null;
  onLaunch: () => void;
  /** True once the completed analysis yields at least one check to pentest. */
  planReady: boolean;
  /** True when the Pentest tab is reachable (the lifted plan is non-empty). */
  pentestReady: boolean;
  onGoToPentest: () => void;
  /** Terminate the running analysis and kill all MCP tools. */
  onTerminate: () => void;
  terminating: boolean;
  termination: TerminationResult | null;
  terminationError: string | null;
}

export function LaunchControl({
  selectedCount,
  job,
  launching,
  error,
  onLaunch,
  planReady,
  pentestReady,
  onGoToPentest,
  onTerminate,
  terminating,
  termination,
  terminationError,
}: LaunchControlProps) {
  const running = job?.status === "running";
  const disabled = selectedCount === 0 || launching || running;

  return (
    <div className="launch">
      <button type="button" className="launch__button" disabled={disabled} onClick={onLaunch}>
        {launching
          ? "Launching…"
          : running
            ? "Analysis running…"
            : `Launch analysis (${selectedCount})`}
      </button>
      <button
        type="button"
        className="launch__button launch__button--secondary"
        disabled={!planReady || !pentestReady}
        onClick={onGoToPentest}
        title={planReady ? "Continue to penetration testing" : "Run an analysis first"}
      >
        Go to Pentest →
      </button>
      <TerminateControl
        running={!!running}
        terminating={terminating}
        result={termination}
        error={terminationError}
        onTerminate={onTerminate}
      />
      {job && <JobSummary job={job} />}
      {error && <span className="launch__error">{error}</span>}
    </div>
  );
}

function JobSummary({ job }: { job: JobStatus }) {
  const counts: Record<TaskStatusValue, number> = {
    pending: 0,
    running: 0,
    done: 0,
    error: 0,
    cancelled: 0,
  };
  for (const task of job.tasks) counts[task.status] += 1;
  return (
    <span className="launch__summary">
      {counts.done} done · {counts.pending + counts.running} in progress · {counts.error} error
      {counts.cancelled > 0 && ` · ${counts.cancelled} cancelled`}
    </span>
  );
}
