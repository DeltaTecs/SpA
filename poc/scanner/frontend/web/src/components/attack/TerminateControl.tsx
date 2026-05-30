import type { TerminationResult } from "../../api/types";

interface TerminateControlProps {
  /** Whether a job is currently running (controls button visibility). */
  running: boolean;
  /** A terminate request is in flight. */
  terminating: boolean;
  /** The outcome of the last terminate request, if any. */
  result: TerminationResult | null;
  /** A terminate request failed. */
  error: string | null;
  onTerminate: () => void;
}

/**
 * "Terminate & kill tools" button shared by the Create Plan and Pentest tabs.
 * Stops the analysis and kills all MCP tools and their tool processes, then
 * reports the per-server outcome.
 */
export function TerminateControl({
  running,
  terminating,
  result,
  error,
  onTerminate,
}: TerminateControlProps) {
  if (!running && !result && !error) return null;
  return (
    <>
      {running && (
        <button
          type="button"
          className="launch__button launch__button--danger"
          disabled={terminating}
          onClick={onTerminate}
          title="Stop the analysis and kill all MCP tools and their tool processes"
        >
          {terminating ? "Terminating…" : "Terminate & kill tools"}
        </button>
      )}
      {result && <TerminationSummary result={result} />}
      {error && <span className="launch__error">{error}</span>}
    </>
  );
}

function TerminationSummary({ result }: { result: TerminationResult }) {
  if (result.tools.length === 0) {
    return <span className="launch__termination">Terminated. No active tool processes to kill.</span>;
  }
  const stopped = result.tools.filter((tool) => tool.ok).map((tool) => tool.name);
  const failed = result.tools.filter((tool) => !tool.ok).map((tool) => tool.name);
  return (
    <span className="launch__termination">
      Terminated.
      {stopped.length > 0 && ` Killed tool processes on: ${stopped.join(", ")}.`}
      {failed.length > 0 && (
        <span className="launch__error"> Could not reach: {failed.join(", ")}.</span>
      )}
    </span>
  );
}
