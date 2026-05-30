import type { ProviderOption } from "../../api/types";
import type { LlmFieldValues, PentestUiConfig } from "./types";

/**
 * localStorage key for the Analysis Queue configuration. Version-suffixed so a
 * future breaking change to `PentestUiConfig` can be rolled by bumping the
 * version, cleanly discarding incompatible stored data instead of crashing.
 */
const STORAGE_KEY = "spa.analysisQueue.config.v1";

/**
 * Read the persisted pentest configuration, or `null` when absent or unreadable
 * (missing/corrupt/unparseable data, or storage disabled). Never throws, so a
 * bad value can't break application boot.
 */
export function loadStoredConfig(): PentestUiConfig | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as PentestUiConfig;
  } catch {
    return null;
  }
}

/** Persist the pentest configuration. Tolerates quota errors / disabled storage. */
export function saveStoredConfig(config: PentestUiConfig): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch {
    /* best-effort: storage full or unavailable */
  }
}

/** Drop the persisted configuration (used by "Reset to defaults"). */
export function clearStoredConfig(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* best-effort */
  }
}

/**
 * If the chosen provider is no longer offered by the backend, fall back to the
 * first available provider's defaults (mirrors `setProvider` in
 * `LlmProviderFields`). Returns the input unchanged when it's already valid.
 */
function reconcileProvider(
  values: LlmFieldValues,
  providers: ProviderOption[],
): LlmFieldValues {
  if (providers.some((p) => p.type === values.provider)) return values;
  const fallback = providers[0];
  if (!fallback) return values;
  return {
    ...values,
    provider: fallback.type,
    model: fallback.default_model ?? "",
    reasoningEffort: "",
  };
}

/**
 * Validate a restored config against the available provider catalogue. A
 * provider that has since become unavailable (e.g. its API key was removed)
 * would otherwise render a broken `<select>` or be posted to the backend; this
 * reconciles both the agent and reviewer providers to a valid choice. Pure /
 * idempotent: returns an equivalent config when nothing drifted.
 */
export function reconcileConfig(
  config: PentestUiConfig,
  providers: ProviderOption[],
): PentestUiConfig {
  if (providers.length === 0) return config;
  return {
    ...config,
    agent: reconcileProvider(config.agent, providers),
    reviewer: reconcileProvider(config.reviewer, providers),
  };
}
