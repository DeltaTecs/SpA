import { useEffect, useState } from "react";
import type { ProviderOption, TaskTypeInfo } from "../../api/types";
import { LlmProviderFields } from "./LlmProviderFields";
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
  const selectedTask = tasks.find((task) => task.task_type === value.taskType);

  useEffect(() => {
    setPromptEditorOpen(false);
  }, [value.taskType]);

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
      <LlmProviderFields
        providers={providers}
        value={{
          provider: value.provider,
          model: value.model,
          reasoningEffort: value.reasoningEffort,
          maxIterations: value.maxIterations,
        }}
        onChange={(fields) => onChange({ ...value, ...fields })}
        disabled={disabled}
      />

      <label className="field">
        <span>Analysis</span>
        <select disabled={disabled} value={value.taskType} onChange={(e) => setTaskType(e.target.value)}>
          {tasks.map((task) => (
            <option key={task.task_type} value={task.task_type}>
              {task.title}
            </option>
          ))}
        </select>
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
