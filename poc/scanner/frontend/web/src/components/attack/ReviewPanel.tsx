import { useState } from "react";
import { submitReview } from "../../api/pentest";
import type { PendingReview } from "../../api/types";
import { ToolCallArguments } from "./ToolCallArguments";

export interface ReviewEntry {
  review: PendingReview;
  itemTitle: string;
}

interface ReviewPanelProps {
  jobId: string;
  entries: ReviewEntry[];
}

export function ReviewPanel({ jobId, entries }: ReviewPanelProps) {
  if (entries.length === 0) return null;
  return (
    <section className="panel review-panel">
      <h2 className="panel__title">
        Tool reviews pending <span className="review-panel__count">{entries.length}</span>
      </h2>
      {entries.map((entry) => (
        <ReviewCard key={entry.review.review_id} jobId={jobId} entry={entry} />
      ))}
    </section>
  );
}

function ReviewCard({ jobId, entry }: { jobId: string; entry: ReviewEntry }) {
  const { review, itemTitle } = entry;
  const [hint, setHint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Resolve the review. `overrideHint`, when given, replaces the typed hint — used
  // by the "forward auto-reviewer's reason" action to send that exact text instead.
  async function decide(approved: boolean, overrideHint?: string) {
    // Stay busy until the next poll drops this card; reset only on failure.
    setBusy(true);
    setError(null);
    try {
      await submitReview(jobId, review.review_id, {
        approved,
        hint: overrideHint ?? hint,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }

  return (
    <article className="review">
      <header className="review__head">
        <span className="review__label">Tool call</span>
        <code className="review__tool">{review.tool_name}</code>
        <span className="review__item">{itemTitle}</span>
      </header>
      <ToolCallArguments args={review.arguments} />
      {review.auto_reason && (
        <div className="review__auto">
          <p className="review__auto-text">
            <strong>Auto-reviewer:</strong> {review.auto_reason}
          </p>
          {/* One-click escalation outcome: deny and hand the auto-reviewer's own
              reason back to the acting model so it knows why and can adjust. */}
          <button
            type="button"
            className="review__forward"
            disabled={busy}
            onClick={() => decide(false, review.auto_reason ?? "")}
          >
            Deny &amp; send this reason to the model
          </button>
        </div>
      )}
      <textarea
        className="review__hint"
        rows={2}
        placeholder="Optional hint to the model (used when denying)"
        value={hint}
        disabled={busy}
        onChange={(e) => setHint(e.target.value)}
      />
      <div className="review__actions">
        <button
          type="button"
          className="review__accept"
          disabled={busy}
          onClick={() => decide(true)}
        >
          Accept
        </button>
        <button
          type="button"
          className="review__deny"
          disabled={busy}
          onClick={() => decide(false)}
        >
          Deny
        </button>
      </div>
      {error && <span className="launch__error">{error}</span>}
    </article>
  );
}
