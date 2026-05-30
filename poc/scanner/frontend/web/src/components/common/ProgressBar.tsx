/** A determinate progress bar.
 *
 * Renders one filled track. Pass `tone` to colour the fill (e.g. amber while a
 * run finished with some failures). The optional `indeterminate` flag animates
 * the fill when the fraction is not yet meaningful (e.g. a job just launched).
 */
export type ProgressTone = "accent" | "success" | "warning";

interface ProgressBarProps {
  /** Completed fraction in the range [0, 1]; clamped defensively. */
  value: number;
  tone?: ProgressTone;
  indeterminate?: boolean;
  /** Accessible label describing what is progressing. */
  ariaLabel?: string;
}

export function ProgressBar({
  value,
  tone = "accent",
  indeterminate = false,
  ariaLabel,
}: ProgressBarProps) {
  const pct = Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div
      className={`progress-bar${indeterminate ? " progress-bar--indeterminate" : ""}`}
      role="progressbar"
      aria-label={ariaLabel}
      aria-valuemin={indeterminate ? undefined : 0}
      aria-valuemax={indeterminate ? undefined : 100}
      aria-valuenow={indeterminate ? undefined : pct}
    >
      <div
        className={`progress-bar__fill progress-bar__fill--${tone}`}
        style={indeterminate ? undefined : { width: `${pct}%` }}
      />
    </div>
  );
}
