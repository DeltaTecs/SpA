import { useState } from "react";
import type { McpToolsetInfo, ProviderOption, ReviewMode, ToolCategory } from "../../api/types";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { LlmProviderFields } from "./LlmProviderFields";
import type { PentestUiConfig } from "./types";

const CATEGORY_LABELS: Record<ToolCategory, string> = {
  db: "Database tools",
  search: "Web search",
  bash: "Bash",
  hexstrike: "HexStrike tools",
};

interface McpToolConfigProps {
  value: PentestUiConfig;
  onChange: (next: PentestUiConfig) => void;
  toolsets: McpToolsetInfo[] | undefined;
  toolsLoading: boolean;
  toolsError: string | null;
  providers: ProviderOption[];
  disabled?: boolean;
}

export function McpToolConfig({
  value,
  onChange,
  toolsets,
  toolsLoading,
  toolsError,
  providers,
  disabled,
}: McpToolConfigProps) {
  const [toolsOpen, setToolsOpen] = useState(false);
  const allowed = new Set(value.allowedTools);

  function setAllowed(next: Set<string>) {
    onChange({ ...value, allowedTools: [...next] });
  }

  function toggleTool(name: string) {
    const next = new Set(allowed);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setAllowed(next);
  }

  function setGroup(names: string[], on: boolean) {
    const next = new Set(allowed);
    for (const name of names) {
      if (on) next.add(name);
      else next.delete(name);
    }
    setAllowed(next);
  }

  function setReviewMode(mode: ReviewMode) {
    onChange({ ...value, reviewMode: mode });
  }

  return (
    <div className="tool-config">
      <label className="tool-config__check">
        <input
          type="checkbox"
          disabled={disabled}
          checked={value.exemptDbSearch}
          onChange={(e) => onChange({ ...value, exemptDbSearch: e.target.checked })}
        />
        <span>Allow database tools &amp; web search without approval</span>
      </label>

      <div className="tool-config__tools">
        <button
          type="button"
          className="provider-form__prompt-button"
          onClick={() => setToolsOpen((open) => !open)}
          aria-expanded={toolsOpen}
        >
          {toolsOpen ? "Hide available tools" : `Select tools (${allowed.size} enabled)`}
        </button>
        {toolsOpen && (
          <div className="tool-list">
            {toolsLoading && <Loading label="Discovering MCP tools..." />}
            {toolsError && <ErrorBanner message={toolsError} />}
            {toolsets?.map((toolset) => {
              const names = toolset.tools.map((tool) => tool.name);
              const allOn = names.length > 0 && names.every((name) => allowed.has(name));
              return (
                <div key={toolset.name} className="tool-group">
                  <div className="tool-group__head">
                    <span className="tool-group__title">
                      {CATEGORY_LABELS[toolset.category]}{" "}
                      <span className="muted">({toolset.name})</span>
                    </span>
                    {names.length > 0 && (
                      <button
                        type="button"
                        className="tool-group__toggle"
                        disabled={disabled}
                        onClick={() => setGroup(names, !allOn)}
                      >
                        {allOn ? "Clear" : "Select all"}
                      </button>
                    )}
                  </div>
                  {names.length === 0 && (
                    <p className="muted tool-group__empty">No tools available (server unreachable?).</p>
                  )}
                  {toolset.tools.map((tool) => (
                    <label key={tool.name} className="tool-row">
                      <input
                        type="checkbox"
                        disabled={disabled}
                        checked={allowed.has(tool.name)}
                        onChange={() => toggleTool(tool.name)}
                      />
                      <span className="tool-row__name">{tool.name}</span>
                      {tool.description && (
                        <span className="tool-row__desc">{tool.description}</span>
                      )}
                    </label>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <label className="field tool-config__constraints">
        <span>Tool-use constraints</span>
        <textarea
          rows={3}
          disabled={disabled}
          placeholder="e.g. Rate-limit all active scans to 10 requests/second."
          value={value.toolConstraints}
          onChange={(e) => onChange({ ...value, toolConstraints: e.target.value })}
        />
        <span className="provider-form__hint">
          Given to the pentest agent and, in automatic review, enforced by the reviewer — it
          rejects tool calls that violate a stated constraint (e.g. missing rate limiting).
        </span>
      </label>

      <fieldset className="tool-config__review">
        <legend>Tool review</legend>
        <label className="tool-config__radio">
          <input
            type="radio"
            name="review-mode"
            disabled={disabled}
            checked={value.reviewMode === "manual"}
            onChange={() => setReviewMode("manual")}
          />
          <span>
            <strong>Manual</strong> — approve or deny each non-exempt tool call yourself.
          </span>
        </label>
        <label className="tool-config__radio">
          <input
            type="radio"
            name="review-mode"
            disabled={disabled}
            checked={value.reviewMode === "automatic"}
            onChange={() => setReviewMode("automatic")}
          />
          <span>
            <strong>Automatic</strong> — a reviewer model judges each non-exempt tool call.
          </span>
        </label>

        {value.reviewMode === "automatic" && (
          <div className="tool-config__reviewer">
            <div className="provider-form">
              <LlmProviderFields
                providers={providers}
                value={value.reviewer}
                onChange={(reviewer) => onChange({ ...value, reviewer })}
                disabled={disabled}
              />
            </div>
            <label className="tool-config__check">
              <input
                type="checkbox"
                disabled={disabled}
                checked={value.reviewAutoDeniedManually}
                onChange={(e) =>
                  onChange({ ...value, reviewAutoDeniedManually: e.target.checked })
                }
              />
              <span>Manually review auto-denied tool calls</span>
            </label>
          </div>
        )}
      </fieldset>
    </div>
  );
}
