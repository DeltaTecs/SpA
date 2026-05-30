import { useState } from "react";
import type {
  Exchange,
  ExchangeTaskStatus,
  HttpExchangeInfo,
  TaskResult,
  TaskStatusValue,
  VulnerabilityCheck,
} from "../../api/types";
import { formatBytes } from "../../lib/format";
import { ExchangeEvidence } from "./ExchangeEvidence";
import { CheckCard } from "./results/CheckCard";
import { renderTaskResult } from "./results/resultRenderers";
import type { EditableExchange } from "./types";

interface ExchangeItemProps {
  item: EditableExchange;
  task?: ExchangeTaskStatus;
  onToggle: (id: string) => void;
  onEdit: (id: string, patch: Partial<Exchange>) => void;
  /** Selected pentest-item ids (`${exchangeId}#${idx}`) for the suggested checks. */
  selectedCheckIds: Set<string>;
  onToggleCheck: (checkId: string) => void;
  onQueueCustom: (exchangeId: string, description: string) => void;
}

export function ExchangeItem({
  item,
  task,
  onToggle,
  onEdit,
  selectedCheckIds,
  onToggleCheck,
  onQueueCustom,
}: ExchangeItemProps) {
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
          {task && (
            <Annotation
              task={task}
              exchangeId={item.id}
              selectedCheckIds={selectedCheckIds}
              onToggleCheck={onToggleCheck}
            />
          )}
          <CustomAnalysis exchangeId={item.id} onQueue={onQueueCustom} />
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

function Annotation({
  task,
  exchangeId,
  selectedCheckIds,
  onToggleCheck,
}: {
  task: ExchangeTaskStatus;
  exchangeId: string;
  selectedCheckIds: Set<string>;
  onToggleCheck: (checkId: string) => void;
}) {
  return (
    <div className="exchange__annotation">
      <div className="exchange__annotation-title">
        Suggested checks
        {task.stopped_on_limit ? " (stopped on iteration limit)" : ""}
      </div>
      {task.status === "pending" && <div className="muted">Queued...</div>}
      {task.status === "running" && <div className="muted">Analysing...</div>}
      {task.status === "cancelled" && <div className="muted">Terminated by operator.</div>}
      {task.status === "error" && (
        <div className="state state--error">{task.error ?? "Analysis failed."}</div>
      )}
      {task.status === "done" && task.result && (
        <SelectableChecks
          result={task.result}
          exchangeId={exchangeId}
          selectedCheckIds={selectedCheckIds}
          onToggleCheck={onToggleCheck}
        />
      )}
    </div>
  );
}

/** Suggested `vulnerability_checks` rendered with a per-check queue checkbox.
 *  Other task types fall back to the read-only generic renderer. */
function SelectableChecks({
  result,
  exchangeId,
  selectedCheckIds,
  onToggleCheck,
}: {
  result: TaskResult;
  exchangeId: string;
  selectedCheckIds: Set<string>;
  onToggleCheck: (checkId: string) => void;
}) {
  if (result.task_type !== "vulnerability_checks") return <>{renderTaskResult(result)}</>;

  const checks = (result.payload.checks as VulnerabilityCheck[] | undefined) ?? [];
  const warning = result.payload.parse_warning as string | undefined;

  return (
    <div className="checks">
      {warning && <div className="checks__warning">{warning}</div>}
      {checks.length === 0 && !warning && <div className="muted">No checks suggested.</div>}
      {checks.map((check, index) => {
        const checkId = `${exchangeId}#${index}`;
        return (
          <CheckCard
            key={index}
            check={check}
            selection={{
              checked: selectedCheckIds.has(checkId),
              onToggle: () => onToggleCheck(checkId),
            }}
          />
        );
      })}
    </div>
  );
}

function CustomAnalysis({
  exchangeId,
  onQueue,
}: {
  exchangeId: string;
  onQueue: (exchangeId: string, description: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");

  function submit() {
    const trimmed = text.trim();
    if (!trimmed) return;
    onQueue(exchangeId, trimmed);
    setText("");
    setOpen(false);
  }

  if (!open) {
    return (
      <div className="custom-analysis">
        <button type="button" className="custom-analysis__open" onClick={() => setOpen(true)}>
          + Queue custom analysis
        </button>
      </div>
    );
  }

  return (
    <div className="custom-analysis custom-analysis--open">
      <textarea
        className="custom-analysis__input"
        rows={3}
        placeholder="Describe the analysis to run against this exchange…"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      <div className="custom-analysis__actions">
        <button
          type="button"
          className="launch__button"
          disabled={text.trim().length === 0}
          onClick={submit}
        >
          Queue analysis
        </button>
        <button
          type="button"
          className="launch__button launch__button--secondary"
          onClick={() => {
            setOpen(false);
            setText("");
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: TaskStatusValue }) {
  const labels: Record<TaskStatusValue, string> = {
    done: "done",
    error: "error",
    running: "running...",
    cancelled: "cancelled",
    pending: "queued",
  };
  return <span className={`task-status task-status--${status}`}>{labels[status]}</span>;
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
