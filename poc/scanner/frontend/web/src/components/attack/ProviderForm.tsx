import { useEffect, useState } from "react";
import type { ProviderOption, ReasoningEffort, TaskTypeInfo } from "../../api/types";
import { PromptEditor } from "./PromptEditor";
import type { PlanConfig } from "./types";
import { taskPromptDefaults } from "./types";

interface ProviderFormProps {
  providers: ProviderOption[];
  tasks: TaskTypeInfo[];
  value: PlanConfig;
  onChange: (next: PlanConfig) => void;
  disabled?: boolean;
}

export function ProviderForm({ providers, tasks, value, onChange, disabled }: ProviderFormProps) {
  const [promptEditorOpen, setPromptEditorOpen] = useState(false);
  const current = providers.find((p) => p.type === value.provider);
  // Keyed providers (openai/deepseek) pick from a fixed model list; keyless
  // local providers accept a free-text model name.
  const freeTextModel = current ? !current.requires_key : true;
  const reasoningEffortOptions = current?.reasoning_effort_options ?? [];
  const selectedTask = tasks.find((task) => task.task_type === value.taskType);

  useEffect(() => {
    setPromptEditorOpen(false);
  }, [value.taskType]);

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

  function setTaskType(taskType: string) {
    const task = tasks.find((candidate) => candidate.task_type === taskType);
    onChange({
      ...value,
      taskType,
      promptOverrides: taskPromptDefaults(task),
    });
  }

  function setPromptPart(id: string, content: string) {
    onChange({
      ...value,
      promptOverrides: {
        ...value.promptOverrides,
        [id]: content,
      },
    });
  }

  return (
    <div className="provider-form">
      <label className="field">
        <span>Provider</span>
        <select
          disabled={disabled}
          value={value.provider}
          onChange={(e) => setProvider(e.target.value)}
        >
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
              onChange({
                ...value,
                reasoningEffort: e.target.value as ReasoningEffort | "",
              })
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

      <label className="field">
        <span>Analysis</span>
        <select
          disabled={disabled}
          value={value.taskType}
          onChange={(e) => setTaskType(e.target.value)}
        >
          {tasks.map((task) => (
            <option key={task.task_type} value={task.task_type}>
              {task.title}
            </option>
          ))}
        </select>
      </label>

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

      {selectedTask && <p className="provider-form__hint">{selectedTask.description}</p>}
      {selectedTask && selectedTask.prompt_parts.length > 0 && (
        <div className="provider-form__prompt">
          <button
            type="button"
            className="provider-form__prompt-button"
            onClick={() => setPromptEditorOpen((open) => !open)}
            aria-expanded={promptEditorOpen}
            aria-controls="prompt-editor"
          >
            {promptEditorOpen ? "Hide prompt" : "Edit prompt"}
          </button>
          {promptEditorOpen && (
            <PromptEditor
              id="prompt-editor"
              parts={selectedTask.prompt_parts}
              values={value.promptOverrides}
              onChange={setPromptPart}
              disabled={disabled}
            />
          )}
        </div>
      )}
    </div>
  );
}
