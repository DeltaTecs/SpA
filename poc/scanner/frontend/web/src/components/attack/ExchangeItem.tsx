import { useState } from "react";
import type { Exchange, ExchangeTaskStatus, HttpExchangeInfo, TaskStatusValue } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { ExchangeEvidence } from "./ExchangeEvidence";
import { renderTaskResult } from "./results/resultRenderers";
import type { EditableExchange } from "./types";

interface ExchangeItemProps {
  item: EditableExchange;
  task?: ExchangeTaskStatus;
  onToggle: (id: string) => void;
  onEdit: (id: string, patch: Partial<Exchange>) => void;
}

export function ExchangeItem({ item, task, onToggle, onEdit }: ExchangeItemProps) {
  const [open, setOpen] = useState(false);

  return (
    <article className={`exchange${item.selected ? " exchange--selected" : ""}`}>
      <div className="exchange__head">
        <input
          type="checkbox"
          className="exchange__check"
          checked={item.selected}
          onChange={() => onToggle(item.id)}
          aria-label="Include in analysis"
        />
        <span className={`exchange__badge exchange__badge--${item.kind}`}>
          {item.kind === "http_pair" ? "HTTP" : "CONV"}
        </span>
        <button
          type="button"
          className="exchange__title"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
        >
          {exchangeTitle(item)}
        </button>
        <span className="exchange__meta">
          {formatBytes(item.payload_bytes)} - {item.packet_count} pkt
        </span>
        {task && <StatusBadge status={task.status} />}
        <span className="exchange__chevron" aria-hidden="true">
          {open ? "v" : ">"}
        </span>
      </div>

      {open && (
        <div className="exchange__body">
          <Inspect item={item} onEdit={onEdit} />
          <ExchangeEvidence item={item} />
          {task && <Annotation task={task} />}
        </div>
      )}
    </article>
  );
}

function Inspect({
  item,
  onEdit,
}: {
  item: EditableExchange;
  onEdit: (id: string, patch: Partial<Exchange>) => void;
}) {
  return (
    <dl className="kv">
      {item.transport && <Row label="Transport" value={item.transport} />}
      {item.remote && <Row label="Remote" value={endpoint(item.remote)} />}
      {item.local && <Row label="Local" value={endpoint(item.local)} />}
      {item.protocols.length > 0 && <Row label="Protocols" value={item.protocols.join(" > ")} />}
      {item.representative_packet_ids.length > 0 && (
        <Row label="Packets" value={item.representative_packet_ids.join(", ")} />
      )}
      {item.http && <HttpEdit http={item.http} onChange={(http) => onEdit(item.id, { http })} />}
    </dl>
  );
}

function HttpEdit({
  http,
  onChange,
}: {
  http: HttpExchangeInfo;
  onChange: (http: HttpExchangeInfo) => void;
}) {
  return (
    <>
      {http.method && <Row label="Method" value={http.method} />}
      {http.host && <Row label="Host" value={http.host} />}
      {http.status_code !== null && <Row label="Status" value={String(http.status_code)} />}
      <div className="kv__row">
        <dt>Endpoint</dt>
        <dd>
          <input
            className="exchange__input"
            value={http.endpoint_path ?? ""}
            onChange={(e) => onChange({ ...http, endpoint_path: e.target.value })}
          />
        </dd>
      </div>
      <div className="kv__row">
        <dt>Params</dt>
        <dd>
          <input
            className="exchange__input"
            value={http.param_names.join(", ")}
            placeholder="comma, separated"
            onChange={(e) => onChange({ ...http, param_names: splitParams(e.target.value) })}
          />
        </dd>
      </div>
    </>
  );
}

function Annotation({ task }: { task: ExchangeTaskStatus }) {
  return (
    <div className="exchange__annotation">
      <div className="exchange__annotation-title">
        Suggested checks
        {task.stopped_on_limit ? " (stopped on iteration limit)" : ""}
      </div>
      {task.status === "pending" && <div className="muted">Queued...</div>}
      {task.status === "running" && <div className="muted">Analysing...</div>}
      {task.status === "error" && (
        <div className="state state--error">{task.error ?? "Analysis failed."}</div>
      )}
      {task.status === "done" && task.result && renderTaskResult(task.result)}
    </div>
  );
}

function StatusBadge({ status }: { status: TaskStatusValue }) {
  const label =
    status === "done"
      ? "done"
      : status === "error"
        ? "error"
        : status === "running"
          ? "running..."
          : "queued";
  return <span className={`task-status task-status--${status}`}>{label}</span>;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="kv__row">
      <dt>{label}</dt>
      <dd className="mono">{value}</dd>
    </div>
  );
}

function endpoint(value: { ip: string | null; port: number | null }): string {
  return `${value.ip ?? "?"}:${value.port ?? "?"}`;
}

function exchangeTitle(item: EditableExchange): string {
  if (item.kind === "http_pair" && item.http) {
    const method = item.http.method ?? "?";
    const path = item.http.endpoint_path ?? item.http.path ?? "/";
    const host = item.http.host ? ` @ ${item.http.host}` : "";
    return `${method} ${path}${host}`;
  }
  return `${item.transport ?? "?"} ${item.remote ? endpoint(item.remote) : "unknown"}`;
}

function splitParams(value: string): string[] {
  return value
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
}
