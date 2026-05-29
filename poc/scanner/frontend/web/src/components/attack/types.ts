import type {
  Exchange,
  PentestItemInput,
  ReasoningEffort,
  ReviewMode,
  TaskPromptPart,
  TaskTypeInfo,
} from "../../api/types";

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

/** A completed analysis plan, lifted to the Attack page to drive the Pentest tab. */
export interface PentestPlan {
  recordingId: number;
  items: PentestItemInput[];
}

/** The provider/model/effort/iterations subset shared by every LLM config form. */
export interface LlmFieldValues {
  provider: string;
  model: string;
  reasoningEffort: ReasoningEffort | "";
  maxIterations: number;
}

/** Camel-cased Pentest tab configuration (converted to the request at submit). */
export interface PentestUiConfig {
  agent: LlmFieldValues;
  exemptDbSearch: boolean;
  allowedTools: string[];
  toolConstraints: string;
  reviewMode: ReviewMode;
  reviewer: LlmFieldValues;
  reviewAutoDeniedManually: boolean;
  concurrent: boolean;
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
