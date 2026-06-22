import type { TaskPromptPart } from "../../api/types";

interface PromptEditorProps {
  id?: string;
  parts: TaskPromptPart[];
  values: Record<string, string>;
  onChange: (id: string, content: string) => void;
  disabled?: boolean;
}

export function PromptEditor({ id, parts, values, onChange, disabled }: PromptEditorProps) {
  if (parts.length === 0) return null;

  return (
    <div id={id} className="prompt-editor">
      <h3 className="prompt-editor__title">Prompt</h3>
      <div className="prompt-editor__grid">
        {parts.map((part) => {
          const value = values[part.id] ?? part.content;
          return (
            <label key={part.id} className="prompt-editor__field">
              <span className="prompt-editor__label">
                <span>{part.title}</span>
                <span className={`prompt-editor__scope prompt-editor__scope--${part.scope}`}>
                  {part.scope}
                </span>
              </span>
              <textarea
                disabled={disabled}
                value={value}
                rows={7}
                onChange={(event) => onChange(part.id, event.target.value)}
              />
            </label>
          );
        })}
      </div>
    </div>
  );
}
