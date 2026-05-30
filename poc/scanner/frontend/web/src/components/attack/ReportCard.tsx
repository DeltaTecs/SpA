import type { PentestItemStatus } from "../../api/types";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { renderTaskResult } from "./results/resultRenderers";

/** One investigated check: status, verdict/evidence, and any error or limit note. */
export function ReportCard({ item }: { item: PentestItemStatus }) {
  return (
    <article className="report-card">
      <header className="report-card__head">
        <span className={`task-status task-status--${item.status}`}>{item.status}</span>
        <h4 className="report-card__title">{item.title}</h4>
      </header>
      {item.status === "running" && <Loading label={item.activity ?? "Investigating…"} />}
      {item.status === "cancelled" && <p className="muted">Terminated by operator.</p>}
      {item.error && <ErrorBanner message={item.error} />}
      {item.result && renderTaskResult(item.result)}
      {item.stopped_on_limit && (
        <p className="muted">Stopped on iteration limit ({item.iterations} iterations).</p>
      )}
    </article>
  );
}
