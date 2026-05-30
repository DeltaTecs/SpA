import { useState } from "react";
import { describeToolArguments, formatToolArgumentsRaw } from "../../lib/toolArguments";

interface ToolCallArgumentsProps {
  args: Record<string, unknown>;
}

export function ToolCallArguments({ args }: ToolCallArgumentsProps) {
  const [showRaw, setShowRaw] = useState(false);
  const fields = describeToolArguments(args);

  if (fields.length === 0) {
    return <div className="tool-args__empty">No arguments</div>;
  }

  return (
    <div className="tool-args">
      <div className="tool-args__toolbar">
        <button
          type="button"
          className="tool-args__toggle"
          onClick={() => setShowRaw((value) => !value)}
        >
          {showRaw ? "Readable" : "Raw JSON"}
        </button>
      </div>
      {showRaw ? (
        <pre className="json-block tool-args__raw">{formatToolArgumentsRaw(args)}</pre>
      ) : (
        <dl className="tool-args__list">
          {fields.map((field) => (
            <div className="tool-args__row" key={field.key}>
              <dt className="tool-args__key">{field.key}</dt>
              <dd className="tool-args__value">
                {field.kind === "text" && !field.multiline ? (
                  <span className="tool-args__inline">{field.value}</span>
                ) : (
                  <pre className="tool-args__block">{field.value}</pre>
                )}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}
