import type { TaskStatusValue } from "../../api/types";
import { ProgressBar, type ProgressTone } from "../common/ProgressBar";

/** The minimal per-session shape this widget needs from a job's tasks/items. */
export interface JobProgressItem {
  status: TaskStatusValue;
  /** Current phase phrase while running (null when not running). */
  activity: string | null;
}

interface JobProgressProps {
  items: JobProgressItem[];
  /** Singular noun for one unit of work (pluralised with a trailing "s"). */
  unitLabel: string;
}

/** Shown for a running session whose phase has not been reported yet. */
const FALLBACK_ACTIVITY = "working…";

type Counts = Record<TaskStatusValue, number>;

function tally(items: JobProgressItem[]): Counts {
  const counts: Counts = { pending: 0, running: 0, done: 0, error: 0, cancelled: 0 };
  for (const item of items) counts[item.status] += 1;
  return counts;
}

/** Collapse repeated phrases into "phrase ×N" (singletons stay bare). */
function summariseActivities(phrases: string[]): string[] {
  const order: string[] = [];
  const counts = new Map<string, number>();
  for (const phrase of phrases) {
    if (!counts.has(phrase)) order.push(phrase);
    counts.set(phrase, (counts.get(phrase) ?? 0) + 1);
  }
  return order.map((phrase) => {
    const n = counts.get(phrase) ?? 1;
    return n > 1 ? `${phrase} ×${n}` : phrase;
  });
}

/** The "current action" line: what running sessions are doing, plus a queued tail. */
function actionLabel(items: JobProgressItem[], counts: Counts): string | null {
  const inProgress = counts.pending + counts.running;
  if (inProgress === 0) return null;
  const phrases = items
    .filter((item) => item.status === "running")
    .map((item) => item.activity ?? FALLBACK_ACTIVITY);
  const parts = summariseActivities(phrases);
  if (counts.pending > 0) parts.push(`${counts.pending} queued`);
  return parts.join(" · ");
}

export function JobProgress({ items, unitLabel }: JobProgressProps) {
  const total = items.length;
  if (total === 0) return null;

  const counts = tally(items);
  const finished = counts.done + counts.error + counts.cancelled;
  const inProgress = counts.pending + counts.running;
  const fraction = finished / total;

  const hasFailures = counts.error > 0 || counts.cancelled > 0;
  const tone: ProgressTone =
    inProgress === 0 ? (hasFailures ? "warning" : "success") : "accent";

  const action = actionLabel(items, counts);
  const unit = total === 1 ? unitLabel : `${unitLabel}s`;

  const detail: string[] = [`${counts.done} done`];
  if (inProgress > 0) detail.push(`${inProgress} in progress`);
  if (counts.error > 0) detail.push(`${counts.error} error`);
  if (counts.cancelled > 0) detail.push(`${counts.cancelled} cancelled`);

  // Before the first session finishes a determinate bar would sit frozen at 0%
  // (a single long check can stay there for minutes), so sweep until then.
  const indeterminate = finished === 0 && inProgress > 0;

  return (
    <div className="job-progress">
      <ProgressBar
        value={fraction}
        tone={tone}
        indeterminate={indeterminate}
        ariaLabel={`${finished} of ${total} ${unit} complete`}
      />
      <div className="job-progress__meta">
        <span className="job-progress__count">
          {finished}/{total} {unit}
        </span>
        <span className="job-progress__detail">{detail.join(" · ")}</span>
      </div>
      {action && (
        <div className="job-progress__action">
          <span className="job-progress__pulse" aria-hidden="true" />
          {action}
        </div>
      )}
    </div>
  );
}
