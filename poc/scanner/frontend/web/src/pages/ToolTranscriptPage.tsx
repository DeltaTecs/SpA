import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import {
  getExploitTranscript,
  getGuidedTranscript,
  getPentestTranscript,
  getScanTranscript,
} from "../api/transcript";
import type { TranscriptDoc, TranscriptStep } from "../api/types";
import { TranscriptStepView } from "../components/tooltranscript/TranscriptStepView";

type Source = "pentest" | "exploit" | "scan" | "guided";

/** One rendered block of transcript (a single analysis, or one guided turn). */
interface Segment {
  title?: string;
  doc?: TranscriptDoc;
  error?: string;
}

const SOURCE_TITLES: Record<Source, string> = {
  pentest: "Analysis Queue",
  exploit: "Exploit Queue",
  scan: "Saved report",
  guided: "Guided Analysis",
};

function describeError(err: unknown): string {
  if (err instanceof ApiError && err.status === 404) {
    return "Transcript not available - the analysis may have been cleared or the backend restarted.";
  }
  return err instanceof Error ? err.message : String(err);
}

/** Fetch the transcript(s) for the requested source. Throws on a bad request. */
async function loadSegments(params: URLSearchParams): Promise<Segment[]> {
  const source = (params.get("source") ?? "") as Source;
  const itemId = params.get("itemId") ?? "";
  const jobId = params.get("jobId") ?? "";

  switch (source) {
    case "pentest":
    case "exploit": {
      if (!jobId || !itemId) throw new Error("Missing jobId or itemId.");
      const fetcher = source === "pentest" ? getPentestTranscript : getExploitTranscript;
      return [{ doc: await fetcher(jobId, itemId) }];
    }
    case "scan": {
      const scanResultId = Number(params.get("scanResultId"));
      if (!Number.isFinite(scanResultId) || !itemId) {
        throw new Error("Missing scanResultId or itemId.");
      }
      return [{ doc: await getScanTranscript(scanResultId, itemId) }];
    }
    case "guided": {
      const jobIds = (params.get("jobIds") ?? "").split(",").filter(Boolean);
      if (jobIds.length === 0) throw new Error("No chat turns to show yet.");
      // Each turn is fetched independently so one lost turn does not blank the page.
      return Promise.all(
        jobIds.map(async (id, index): Promise<Segment> => {
          const title = `Turn ${index + 1}`;
          try {
            return { title, doc: await getGuidedTranscript(id) };
          } catch (err) {
            return { title, error: describeError(err) };
          }
        }),
      );
    }
    default:
      throw new Error(`Unknown tool transcript source '${source}'.`);
  }
}

/** Hide DB-access / web-search tool steps per the active filters (reasoning is kept). */
function visibleSteps(steps: TranscriptStep[], hideDb: boolean, hideSearch: boolean): TranscriptStep[] {
  return steps.filter((step) => {
    if (step.kind !== "tool_call") return true;
    if (hideDb && step.category === "db") return false;
    if (hideSearch && step.category === "search") return false;
    return true;
  });
}

export function ToolTranscriptPage() {
  const [params] = useSearchParams();
  const source = (params.get("source") ?? "") as Source;
  const [segments, setSegments] = useState<Segment[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hideDb, setHideDb] = useState(false);
  const [hideSearch, setHideSearch] = useState(false);

  // Re-fetch whenever the query string changes (the page is opened per-result).
  const query = params.toString();
  useEffect(() => {
    let cancelled = false;
    setSegments(null);
    setError(null);
    loadSegments(params)
      .then((result) => !cancelled && setSegments(result))
      .catch((err) => !cancelled && setError(describeError(err)));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  useEffect(() => {
    document.title = `Tool Transcript - ${SOURCE_TITLES[source] ?? "Transcript"}`;
  }, [source]);

  const subtitle = useMemo(() => {
    const itemId = params.get("itemId");
    if (source === "scan") return `Scan #${params.get("scanResultId")} - item ${itemId}`;
    if (source === "guided") return `${(params.get("jobIds") ?? "").split(",").filter(Boolean).length} turn(s)`;
    if (itemId) return `Item ${itemId}`;
    return "";
  }, [params, source]);

  return (
    <div className="tool-transcript-page">
      <header className="tool-transcript-page__header">
        <h1>Tool Transcript - {SOURCE_TITLES[source] ?? "Transcript"}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
        <p className="muted tool-transcript-page__intro">
          The MCP tools the agent used to reach this result: each call's arguments and output, the
          reviewer's decision, and the model's reasoning in between. Python code is shown exactly as
          the tool received or wrote it.
        </p>
        <div className="tool-transcript-page__filters">
          <label>
            <input type="checkbox" checked={hideDb} onChange={(e) => setHideDb(e.target.checked)} />
            <span>Hide database access</span>
          </label>
          <label>
            <input
              type="checkbox"
              checked={hideSearch}
              onChange={(e) => setHideSearch(e.target.checked)}
            />
            <span>Hide web search</span>
          </label>
        </div>
      </header>

      {error && <div className="tool-transcript-page__notice tool-transcript-page__notice--error">{error}</div>}
      {!error && segments === null && <p className="muted">Loading transcript...</p>}

      {segments?.map((segment, index) => (
        <ToolTranscriptSegment
          key={segment.title ?? index}
          segment={segment}
          hideDb={hideDb}
          hideSearch={hideSearch}
        />
      ))}
    </div>
  );
}

function ToolTranscriptSegment({
  segment,
  hideDb,
  hideSearch,
}: {
  segment: Segment;
  hideDb: boolean;
  hideSearch: boolean;
}) {
  const steps = segment.doc?.steps ?? [];
  const shown = visibleSteps(steps, hideDb, hideSearch);

  return (
    <section className="tool-transcript-page__segment">
      {segment.title && <h2 className="tool-transcript-page__segment-title">{segment.title}</h2>}
      {segment.error && <div className="tool-transcript-page__notice">{segment.error}</div>}
      {!segment.error && steps.length === 0 && (
        <p className="muted">No tool calls were recorded for this analysis.</p>
      )}
      {!segment.error && steps.length > 0 && shown.length === 0 && (
        <p className="muted">All steps are hidden by the active filters.</p>
      )}
      {shown.map((step, index) => (
        <TranscriptStepView key={step.call_id ?? `${step.kind}-${index}`} step={step} />
      ))}
    </section>
  );
}
