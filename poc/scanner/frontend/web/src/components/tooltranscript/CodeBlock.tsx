import { useEffect, useState } from "react";

interface CodeBlockProps {
  text: string;
  language?: "json" | "python" | "text";
}

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.left = "-9999px";
  document.body.appendChild(field);
  field.select();
  document.execCommand("copy");
  document.body.removeChild(field);
}

function languageLabel(language: CodeBlockProps["language"]): string {
  if (language === "python") return "Python";
  if (language === "json") return "JSON";
  return "Text";
}

/** Copyable code block. The text is rendered exactly as received. */
export function CodeBlock({ text, language = "text" }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);

  function onCopy(): void {
    void copyText(text)
      .then(() => setCopied(true))
      .catch(() => setCopied(false));
  }

  return (
    <div className={`tool-transcript__code-wrap tool-transcript__code-wrap--${language}`}>
      <div className="tool-transcript__code-head">
        <span>{languageLabel(language)}</span>
        <button
          type="button"
          className="tool-transcript__copy"
          onClick={onCopy}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className={`tool-transcript__code tool-transcript__code--${language}`}>
        <code>{text}</code>
      </pre>
    </div>
  );
}
