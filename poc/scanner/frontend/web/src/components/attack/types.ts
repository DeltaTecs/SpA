import type { Exchange, ReasoningEffort } from "../../api/types";

/** An exchange plus its include/exclude selection in the Create Plan list. */
export interface EditableExchange extends Exchange {
  selected: boolean;
}

/** The LLM run configuration chosen in the provider form. */
export interface PlanConfig {
  provider: string;
  model: string;
  reasoningEffort: ReasoningEffort | "";
  taskType: string;
  maxIterations: number;
}

/** Drop the UI-only `selected` flag before posting an exchange to the backend. */
export function toExchange({ selected, ...rest }: EditableExchange): Exchange {
  void selected;
  return rest;
}
