import type { Exchange, ReasoningEffort, TaskPromptPart, TaskTypeInfo } from "../../api/types";

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
  promptOverrides: Record<string, string>;
}

/** Drop the UI-only `selected` flag before posting an exchange to the backend. */
export function toExchange({ selected, ...rest }: EditableExchange): Exchange {
  void selected;
  return rest;
}

export function promptPartDefaults(parts: TaskPromptPart[]): Record<string, string> {
  return Object.fromEntries(parts.map((part) => [part.id, part.content]));
}

export function taskPromptDefaults(task: TaskTypeInfo | undefined): Record<string, string> {
  return promptPartDefaults(task?.prompt_parts ?? []);
}
