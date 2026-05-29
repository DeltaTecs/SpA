import type { ProviderOption, ReasoningEffort } from "../../api/types";
import type { LlmFieldValues } from "./types";

interface LlmProviderFieldsProps {
  providers: ProviderOption[];
  value: LlmFieldValues;
  onChange: (next: LlmFieldValues) => void;
  disabled?: boolean;
}

/**
 * Provider / model / reasoning-effort / max-iterations controls, rendered as a
 * fragment of `.field`s so a parent `.provider-form` lays them out. Shared by the
 * Create Plan form, the pentest agent config, and the auto-reviewer config.
 */
export function LlmProviderFields({
  providers,
  value,
  onChange,
  disabled,
}: LlmProviderFieldsProps) {
  const current = providers.find((p) => p.type === value.provider);
  // Keyed providers (openai/deepseek) pick from a fixed model list; keyless
  // local providers accept a free-text model name.
  const freeTextModel = current ? !current.requires_key : true;
  const reasoningEffortOptions = current?.reasoning_effort_options ?? [];

  function setProvider(type: string) {
    const provider = providers.find((p) => p.type === type);
    const options = provider?.reasoning_effort_options ?? [];
    const reasoningEffort =
      value.reasoningEffort && options.includes(value.reasoningEffort)
        ? value.reasoningEffort
        : "";
    onChange({
      ...value,
      provider: type,
      model: provider?.default_model ?? "",
      reasoningEffort,
    });
  }

  return (
    <>
      <label className="field">
        <span>Provider</span>
        <select disabled={disabled} value={value.provider} onChange={(e) => setProvider(e.target.value)}>
          {providers.map((provider) => (
            <option key={provider.type} value={provider.type}>
              {provider.type}
              {provider.requires_key ? " (API key)" : ""}
            </option>
          ))}
        </select>
      </label>

      <label className="field">
        <span>Model</span>
        {freeTextModel ? (
          <input
            disabled={disabled}
            value={value.model}
            placeholder="model name"
            onChange={(e) => onChange({ ...value, model: e.target.value })}
          />
        ) : (
          <select
            disabled={disabled}
            value={value.model}
            onChange={(e) => onChange({ ...value, model: e.target.value })}
          >
            {(current?.model_options ?? []).map((model) => (
              <option key={model} value={model}>
                {model}
              </option>
            ))}
          </select>
        )}
      </label>

      {reasoningEffortOptions.length > 0 && (
        <label className="field">
          <span>Reasoning effort</span>
          <select
            disabled={disabled}
            value={value.reasoningEffort}
            onChange={(e) =>
              onChange({ ...value, reasoningEffort: e.target.value as ReasoningEffort | "" })
            }
          >
            <option value="">Provider default</option>
            {reasoningEffortOptions.map((effort) => (
              <option key={effort} value={effort}>
                {effort}
              </option>
            ))}
          </select>
        </label>
      )}

      <label className="field field--narrow">
        <span>Max iterations</span>
        <input
          type="number"
          min={1}
          max={50}
          disabled={disabled}
          value={value.maxIterations}
          onChange={(e) => onChange({ ...value, maxIterations: Number(e.target.value) })}
        />
      </label>
    </>
  );
}
