import type { TranscriptCategory, TranscriptStep } from "../../api/types";
import { isScalar, prettyJson, scalarText, tryParseJson } from "./format";

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
  return <div className={`tool-script__text ${className ?? ""}`}>{text}</div>;
}

/** The model's interim reasoning between tool calls. */
function ReasoningBlock({ step }: { step: TranscriptStep }) {
  return (
    <div className="tool-script__step tool-script__reasoning">
      <span className="tool-script__step-label">Model reasoning</span>
      {step.text && <MultilineText text={step.text} />}
      {step.reasoning && (
        <MultilineText text={step.reasoning} className="tool-script__text--muted" />
      )}
    </div>
  );
}

/** One tool argument value: scalars inline, objects/arrays as pretty JSON. */
function ArgumentValue({ value }: { value: unknown }) {
  if (isScalar(value)) {
    return <span className="tool-script__arg-value">{scalarText(value)}</span>;
  }
  return <pre className="tool-script__code">{prettyJson(value)}</pre>;
}

function ArgumentsList({ args }: { args: Record<string, unknown> }) {
  const entries = Object.entries(args);
  if (entries.length === 0) {
    return <p className="muted tool-script__empty">No arguments.</p>;
  }
  return (
    <dl className="tool-script__args">
      {entries.map(([key, value]) => (
        <div key={key} className="tool-script__arg">
          <dt>{key}</dt>
          <dd>
            <ArgumentValue value={value} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Tool output: pretty-printed when it is JSON, otherwise text with newlines kept. */
function OutputBlock({ output }: { output: string }) {
  if (!output.trim()) {
    return <p className="muted tool-script__empty">No output.</p>;
  }
  const parsed = tryParseJson(output);
  if (parsed !== undefined) {
    return <pre className="tool-script__code">{prettyJson(parsed)}</pre>;
  }
  return <MultilineText text={output} />;
}

/** Reviewer verdict badge + reason for one tool call. */
function DecisionBadge({ step }: { step: TranscriptStep }) {
  let cls: string;
  let label: string;
  if (step.approved === true) {
    cls = "tool-script__verdict--approved";
    label = "Approved";
  } else if (step.approved === false) {
    cls = "tool-script__verdict--denied";
    label = "Denied";
  } else {
    cls = "tool-script__verdict--auto";
    label = "Auto-allowed (read-only)";
  }
  return (
    <div className="tool-script__decision">
      <span className={`tool-script__verdict ${cls}`}>{label}</span>
      {step.review_feedback && (
        <span className="tool-script__decision-reason">{step.review_feedback}</span>
      )}
    </div>
  );
}

function ToolCallCard({ step }: { step: TranscriptStep }) {
  return (
    <article className={`tool-script__step tool-script__tool tool-script__tool--${step.category ?? "other"}`}>
      <header className="tool-script__tool-head">
        <span className="tool-script__tool-name mono">{step.tool_name ?? "unknown tool"}</span>
        <span className={`tool-script__cat tool-script__cat--${step.category ?? "other"}`}>
          {categoryLabel(step.category)}
        </span>
      </header>
      <DecisionBadge step={step} />
      <div className="tool-script__field">
        <span className="tool-script__field-label">Arguments</span>
        <ArgumentsList args={step.arguments ?? {}} />
      </div>
      <div className="tool-script__field">
        <span className="tool-script__field-label">Output</span>
        <OutputBlock output={step.output ?? ""} />
      </div>
    </article>
  );
}

/** Render one transcript step (reasoning or an executed tool call). */
export function TranscriptStepView({ step }: { step: TranscriptStep }) {
  return step.kind === "reasoning" ? <ReasoningBlock step={step} /> : <ToolCallCard step={step} />;
}
