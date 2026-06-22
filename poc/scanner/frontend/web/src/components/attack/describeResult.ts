import type { Exchange, PentestReportPayload, TaskResult } from "../../api/types";
import type { CompletedEntry } from "../../state/AnalysisQueueContext";

/**
 * A human-readable description of an exchange's target. HTTP endpoints are
 * rendered as an absolute URL (incl. domain) when the host is known, always
 * followed by the remote `ip:port` and transport so a reader knows exactly what
 * the result refers to. Mirrors the backend `_http_scope` logic in
 * `app/pentest/runner.py`.
 */
export function describeTarget(exchange: Exchange): string {
  const remote = exchange.remote;
  const endpoint = `${remote?.ip ?? "?"}:${remote?.port ?? "?"}`;
  const transport = exchange.transport ? `, ${exchange.transport}` : "";
  const suffix = `(${endpoint}${transport})`;

  const http = exchange.http;
  const path = http?.endpoint_path || http?.path || null;
  if (http && path) {
    if (http.host) {
      const scheme =
        http.scheme ||
        (exchange.protocols.some((p) => p.toUpperCase() === "TLS") ? "https" : "http");
      const separator = path.startsWith("/") ? "" : "/";
      return `${scheme}://${http.host}${separator}${path} ${suffix}`;
    }
    return `HTTP ${path} ${suffix}`;
  }
  return `${endpoint}${exchange.transport ? ` (${exchange.transport})` : ""}`;
}

/** Read the verdict/summary/evidence of a `pentest` task result, if present. */
function pentestPayload(result: TaskResult | null): PentestReportPayload | null {
  if (!result || result.task_type !== "pentest") return null;
  return result.payload as unknown as PentestReportPayload;
}

const VERDICT_LABELS: Record<string, string> = {
  confirmed: "Confirmed",
  inconclusive: "Inconclusive",
  not_exploitable: "Not exploitable",
};

/**
 * A labelled, multi-line description of one completed analysis: what was
 * investigated, the precise target (URL + ip:port), and the outcome. Used both
 * for sending a result into the Guided Analysis chat and for the text export.
 */
export function describeCompletedEntry(entry: CompletedEntry): string {
  const { item, result, label } = entry;
  const lines: string[] = [];
  lines.push(`Analysis: ${result.title}`);
  lines.push(`Source: ${label}`);
  lines.push(`Target: ${describeTarget(item.exchange)}`);
  if (item.check.severity) lines.push(`Severity: ${item.check.severity}`);
  lines.push(`Status: ${result.status}`);

  const payload = pentestPayload(result.result);
  if (payload) {
    if (payload.verdict) lines.push(`Verdict: ${VERDICT_LABELS[payload.verdict] ?? payload.verdict}`);
    if (payload.summary) lines.push(`Summary: ${payload.summary}`);
    if (payload.evidence && payload.evidence.length > 0) {
      lines.push("Evidence:");
      for (const item of payload.evidence) lines.push(`  - ${item}`);
    }
  } else if (result.result) {
    lines.push(`Result: ${JSON.stringify(result.result.payload)}`);
  }

  if (result.error) lines.push(`Error: ${result.error}`);
  if (result.stopped_on_limit) {
    lines.push(`Note: stopped on iteration limit (${result.iterations ?? "?"} iterations).`);
  }
  return lines.join("\n");
}

/** Serialize all completed analyses into a single descriptive text document. */
export function exportCompletedToText(entries: CompletedEntry[]): string {
  const header = [
    "Vulnerability Scanner — Completed Analyses",
    `Exported: ${new Date().toISOString()}`,
    `Total: ${entries.length}`,
  ].join("\n");
  const separator = `\n\n${"=".repeat(72)}\n\n`;
  if (entries.length === 0) return `${header}\n\n(No completed analyses.)\n`;
  return `${header}${separator}${entries.map(describeCompletedEntry).join(separator)}\n`;
}
