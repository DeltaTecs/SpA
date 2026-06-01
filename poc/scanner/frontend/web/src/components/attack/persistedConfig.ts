import type { ProviderOption, TaskTypeInfo } from "../../api/types";
import type { LlmFieldValues, PentestUiConfig, PlanConfig } from "./types";
import { taskPromptDefaults } from "./types";

/**
 * localStorage keys for the persisted page configurations. Version-suffixed so a
 * future breaking change to a config shape can be rolled by bumping the version,
 * cleanly discarding incompatible stored data instead of crashing.
 */
export const ANALYSIS_QUEUE_CONFIG_KEY = "spa.analysisQueue.config.v1";
export const EXPLOIT_QUEUE_CONFIG_KEY = "spa.exploitQueue.config.v1";
export const TEST_PLANNER_CONFIG_KEY = "spa.testPlanner.config.v1";
export const GUIDED_ANALYSIS_CONFIG_KEY = "spa.guidedAnalysis.config.v1";

/** Persisted Guided Analysis chat (messages + draft input), so the conversation
 *  survives a refresh. */
export const GUIDED_ANALYSIS_CHAT_KEY = "spa.guidedAnalysis.chat.v1";

/** Persisted handle to the Test Planner's live job, so progress survives a
 *  refresh. Scoped to the recording + task type it was launched for, so it only
 *  reattaches when the same recording/task is displayed (matching `getLatestScan`). */
export const TEST_PLANNER_JOB_KEY = "spa.testPlanner.job.v1";

/** Persisted snapshot of the Analysis Queue (pending/active/completed lists and
 *  run state), so in-flight investigations resume after a refresh. */
export const ANALYSIS_QUEUE_STATE_KEY = "spa.analysisQueue.state.v1";

/** Persisted snapshot of the Exploit Queue (pending/active/completed lists and
 *  run state), so in-flight exploit sessions resume after a refresh. */
export const EXPLOIT_QUEUE_STATE_KEY = "spa.exploitQueue.state.v1";

/** A reference to a launched Test Planner job and the view it belongs to. */
export interface ActiveJobRef {
  jobId: string;
  recordingId: number;
  taskType: string;
}

/**
 * Fallback provider field values when `currentType` is no longer offered by the
 * backend, or `null` when the current choice is still valid (or no providers are
 * available). Mirrors `setProvider` in `LlmProviderFields`.
 */
function providerFallback(
  currentType: string,
  providers: ProviderOption[],
): Pick<LlmFieldValues, "provider" | "model" | "reasoningEffort"> | null {
  if (providers.length === 0) return null;
  if (providers.some((p) => p.type === currentType)) return null;
  const fallback = providers[0];
  return { provider: fallback.type, model: fallback.default_model ?? "", reasoningEffort: "" };
}

function reconcileLlmFields(values: LlmFieldValues, providers: ProviderOption[]): LlmFieldValues {
  const fallback = providerFallback(values.provider, providers);
  return fallback ? { ...values, ...fallback } : values;
}

/**
 * Validate a restored pentest config against the available provider catalogue. A
 * provider that has since become unavailable (e.g. its API key was removed)
 * would otherwise render a broken `<select>` or be posted to the backend; this
 * reconciles both the agent and reviewer providers to a valid choice. Pure /
 * idempotent: returns an equivalent config when nothing drifted.
 */
export function reconcileConfig<T extends PentestUiConfig>(
  config: T,
  providers: ProviderOption[],
): T {
  if (providers.length === 0) return config;
  return {
    ...config,
    agent: reconcileLlmFields(config.agent, providers),
    reviewer: reconcileLlmFields(config.reviewer, providers),
  };
}

/**
 * Reconcile persisted prompt overrides against a task's current prompt parts:
 * keep the saved text for parts that still exist (the user may have edited it),
 * drop parts the backend removed, and seed defaults for parts it added.
 */
function reconcilePromptOverrides(
  overrides: Record<string, string>,
  task: TaskTypeInfo,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of task.prompt_parts) {
    result[part.id] = part.id in overrides ? overrides[part.id] : part.content;
  }
  return result;
}

/**
 * Validate a restored Test Planner config against the available providers and
 * task types. Falls back to the first provider when the saved one is gone, and
 * to the first task (re-seeding its prompt defaults) when the saved task type is
 * gone; otherwise reconciles the saved prompt overrides to the task's parts.
 * Pure / idempotent.
 */
export function reconcilePlanConfig(
  config: PlanConfig,
  providers: ProviderOption[],
  tasks: TaskTypeInfo[],
): PlanConfig {
  let next = config;

  const fallback = providerFallback(config.provider, providers);
  if (fallback) next = { ...next, ...fallback };

  if (tasks.length > 0) {
    const task = tasks.find((t) => t.task_type === next.taskType);
    if (task) {
      next = { ...next, promptOverrides: reconcilePromptOverrides(next.promptOverrides, task) };
    } else {
      const first = tasks[0];
      next = { ...next, taskType: first.task_type, promptOverrides: taskPromptDefaults(first) };
    }
  }

  return next;
}
