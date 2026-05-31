import type {
  Exchange,
  ProviderOption,
  ReasoningEffort,
  ReviewMode,
  TaskPromptPart,
  TaskTypeInfo,
  VulnerabilityCheck,
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

/**
 * Guided Analysis config: the same agent + tool-review configuration as the
 * pentest tab, plus an editable system-prompt pretext for the chat. The
 * `concurrent` flag is unused here (one turn at a time) but kept for reuse of the
 * shared config form/helpers.
 */
export interface GuidedUiConfig extends PentestUiConfig {
  systemPrompt: string;
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

/** Seed a fresh Test Planner config from the first provider and task type. */
export function seedPlanConfig(provider: ProviderOption, task: TaskTypeInfo): PlanConfig {
  return {
    provider: provider.type,
    model: provider.default_model ?? "",
    reasoningEffort: "",
    taskType: task.task_type,
    maxIterations: 10,
    promptOverrides: taskPromptDefaults(task),
  };
}

/**
 * Synthesize a `VulnerabilityCheck` from a user's free-text custom analysis so
 * it flows through the same pentest pipeline as an LLM-suggested check.
 */
export function customAnalysisCheck(description: string): VulnerabilityCheck {
  return {
    title: "Custom analysis",
    description,
    rationale: "User-requested custom analysis.",
    severity: "info",
    technique: null,
    references: [],
  };
}
