import { buildQuery } from "../../api/client";

/** Where a "Tool script" button points: a live queue item, a saved report, or a chat. */
export type ToolScriptTarget =
  | { source: "pentest" | "exploit"; jobId: string; itemId: string }
  | { source: "scan"; scanResultId: number; itemId: string }
  | { source: "guided"; jobIds: string[] };

/** Open the standalone Tool-script page for a target in a new browser tab. */
export function openToolScript(target: ToolScriptTarget): void {
  let params: Record<string, string>;
  if (target.source === "guided") {
    params = { source: "guided", jobIds: target.jobIds.join(",") };
  } else if (target.source === "scan") {
    params = { source: "scan", scanResultId: String(target.scanResultId), itemId: target.itemId };
  } else {
    params = { source: target.source, jobId: target.jobId, itemId: target.itemId };
  }
  window.open(`/tool-script${buildQuery(params)}`, "_blank", "noopener");
}
