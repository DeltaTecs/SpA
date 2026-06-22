import type { TranscriptCategory, TranscriptStep } from "../../api/types";
import { CodeBlock } from "./CodeBlock";
import {
  childContext,
  containsPythonCode,
  isPlainObject,
  isScalar,
  prettyJson,
  scalarText,
  shouldRenderPythonCode,
  tryParseJson,
  type ValueContext,
} from "./format";

/** Human labels for the coarse tool categories shown as a badge. */
const CATEGORY_LABELS: Record<TranscriptCategory, string> = {
  db: "Database",
  search: "Web search",
  bash: "Shell",
  hexstrike: "Pentest tool",
  other: "Tool",
};

function categoryLabel(category: TranscriptCategory | null | undefined): string {
  return category ? CATEGORY_LABELS[category] : CATEGORY_LABELS.other;
}

/** A multi-line string block: real newlines render as line breaks. */
function MultilineText({ text, className }: { text: string; className?: string }) {
  return <div className={`tool-transcript__text ${className ?? ""}`}>{text}</div>;
}

/** The model's interim reasoning between tool calls. */
function ReasoningBlock({ step }: { step: TranscriptStep }) {
  return (
    <div className="tool-transcript__step tool-transcript__reasoning">
      <span className="tool-transcript__step-label">Model reasoning</span>
      {step.text && <MultilineText text={step.text} />}
      {step.reasoning && (
        <MultilineText text={step.reasoning} className="tool-transcript__text--muted" />
      )}
    </div>
  );
}

/** One nested value. Python code strings stay exact and copyable. */
function TranscriptValue({ value, context }: { value: unknown; context: ValueContext }) {
  if (typeof value === "string" && shouldRenderPythonCode(value, context)) {
    return <CodeBlock text={value} language="python" />;
  }
  if (isScalar(value)) {
    return <span className="tool-transcript__arg-value">{scalarText(value)}</span>;
  }
  if (containsPythonCode(value, context)) {
    return <StructuredValue value={value} context={context} />;
  }
  return <CodeBlock text={prettyJson(value)} language="json" />;
}

function StructuredValue({ value, context }: { value: unknown; context: ValueContext }) {
  if (Array.isArray(value)) {
    return (
      <ol className="tool-transcript__structured tool-transcript__structured--array">
        {value.map((item, index) => (
          <li key={index}>
            <TranscriptValue value={item} context={childContext(context, String(index))} />
          </li>
        ))}
      </ol>
    );
  }

  if (isPlainObject(value)) {
    return (
      <dl className="tool-transcript__structured">
        {Object.entries(value).map(([key, item]) => (
          <div key={key} className="tool-transcript__structured-item">
            <dt>{key}</dt>
            <dd>
              <TranscriptValue value={item} context={childContext(context, key)} />
            </dd>
          </div>
        ))}
      </dl>
    );
  }

  return <span className="tool-transcript__arg-value">{String(value)}</span>;
}

function ArgumentsList({ step }: { step: TranscriptStep }) {
  const args = step.arguments ?? {};
  const entries = Object.entries(args);
  if (entries.length === 0) {
    return <p className="muted tool-transcript__empty">No arguments.</p>;
  }
  return (
    <dl className="tool-transcript__args">
      {entries.map(([key, value]) => (
        <div key={key} className="tool-transcript__arg">
          <dt>{key}</dt>
          <dd>
            <TranscriptValue
              value={value}
              context={{
                key,
                source: "arguments",
                toolName: step.tool_name,
                rootArguments: args,
              }}
            />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Tool output: pretty-printed when it is JSON, otherwise text with newlines kept. */
function OutputBlock({ step }: { step: TranscriptStep }) {
  const output = step.output ?? "";
  if (!output.trim()) {
    return <p className="muted tool-transcript__empty">No output.</p>;
  }

  const parsed = tryParseJson(output);
  if (parsed !== undefined) {
    const context: ValueContext = {
      source: "output",
      toolName: step.tool_name,
      rootArguments: step.arguments ?? {},
    };
    if (containsPythonCode(parsed, context)) {
      return <StructuredValue value={parsed} context={context} />;
    }
    return <CodeBlock text={prettyJson(parsed)} language="json" />;
  }

  return <MultilineText text={output} />;
}

/** Reviewer verdict badge + reason for one tool call. */
function DecisionBadge({ step }: { step: TranscriptStep }) {
  let cls: string;
  let label: string;
  if (step.approved === true) {
    cls = "tool-transcript__verdict--approved";
    label = "Approved";
  } else if (step.approved === false) {
    cls = "tool-transcript__verdict--denied";
    label = "Denied";
  } else {
    cls = "tool-transcript__verdict--auto";
    label = "Auto-allowed (read-only)";
  }
  return (
    <div className="tool-transcript__decision">
      <span className={`tool-transcript__verdict ${cls}`}>{label}</span>
      {step.review_feedback && (
        <span className="tool-transcript__decision-reason">{step.review_feedback}</span>
      )}
    </div>
  );
}

function ToolCallCard({ step }: { step: TranscriptStep }) {
  return (
    <article
      className={`tool-transcript__step tool-transcript__tool tool-transcript__tool--${
        step.category ?? "other"
      }`}
    >
      <header className="tool-transcript__tool-head">
        <span className="tool-transcript__tool-name mono">{step.tool_name ?? "unknown tool"}</span>
        <span className={`tool-transcript__cat tool-transcript__cat--${step.category ?? "other"}`}>
          {categoryLabel(step.category)}
        </span>
      </header>
      <DecisionBadge step={step} />
      <div className="tool-transcript__field">
        <span className="tool-transcript__field-label">Arguments</span>
        <ArgumentsList step={step} />
      </div>
      <div className="tool-transcript__field">
        <span className="tool-transcript__field-label">Output</span>
        <OutputBlock step={step} />
      </div>
    </article>
  );
}

/** Render one transcript step (reasoning or an executed tool call). */
export function TranscriptStepView({ step }: { step: TranscriptStep }) {
  return step.kind === "reasoning" ? <ReasoningBlock step={step} /> : <ToolCallCard step={step} />;
}
