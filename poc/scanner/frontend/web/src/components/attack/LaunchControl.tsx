import type { JobStatus, TerminationResult } from "../../api/types";
import { JobProgress } from "./JobProgress";
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
    <>
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
        {error && <span className="launch__error">{error}</span>}
      </div>
      {job && (
        <JobProgress
          items={job.tasks.map((task) => ({ status: task.status, activity: task.activity }))}
          unitLabel="exchange"
        />
      )}
    </>
  );
}
