import type { ReactNode } from "react";
import type { TaskResult } from "../../../api/types";
import { VulnerabilityChecksResult } from "./VulnerabilityChecksResult";

type ResultRenderer = (result: TaskResult) => ReactNode;

// Maps an analysis task_type to the component that renders its result payload.
// A new task type adds one entry here plus its renderer — JobResults/ExchangeItem
// stay unchanged. Unknown types fall back to a generic JSON view.
const RENDERERS: Record<string, ResultRenderer> = {
  vulnerability_checks: (result) => <VulnerabilityChecksResult result={result} />,
};

export function renderTaskResult(result: TaskResult): ReactNode {
  const renderer = RENDERERS[result.task_type];
  if (renderer) return renderer(result);
  return <pre className="json-block">{JSON.stringify(result.payload, null, 2)}</pre>;
}
