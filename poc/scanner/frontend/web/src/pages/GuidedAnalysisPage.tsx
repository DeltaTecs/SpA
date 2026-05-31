import { useEffect, useRef, useState } from "react";
import { LlmProviderFields } from "../components/attack/LlmProviderFields";
import { McpToolConfig } from "../components/attack/McpToolConfig";
import { ReviewPanel, type ReviewEntry } from "../components/attack/ReviewPanel";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { Loading } from "../components/common/Loading";
import { turnReviews, useGuidedAnalysis } from "../state/GuidedAnalysisContext";

export function GuidedAnalysisPage() {
  const {
    config,
    setConfig,
    resetConfig,
    providers,
    providersError,
    toolsets,
    toolsLoading,
    toolsError,
    messages,
    draft,
    setDraft,
    activeTurn,
    busy,
    error,
    sendMessage,
    submitReview,
    stopTurn,
    clearChat,
  } = useGuidedAnalysis();

  const [promptOpen, setPromptOpen] = useState(false);
  const canSend = !!config && draft.trim().length > 0 && !busy;

  const reviewEntries: ReviewEntry[] = turnReviews(activeTurn).map((review) => ({
    review,
    itemTitle: "Guided analysis",
  }));

  return (
    <div className="page">
      <header className="page__header">
        <h1>Guided Analysis</h1>
      </header>

      <section className="panel">
        <div className="panel__title config-head">
          <span>Chat configuration</span>
          <button
            type="button"
            className="config-reset"
            disabled={busy || !config}
            onClick={resetConfig}
          >
            Reset to defaults
          </button>
        </div>
        {providersError && <ErrorBanner message={providersError} />}
        {config && providers && (
          <div className="provider-form">
            <LlmProviderFields
              providers={providers}
              value={config.agent}
              onChange={(agent) => setConfig({ ...config, agent })}
              disabled={busy}
            />
          </div>
        )}
        {config && providers && (
          <McpToolConfig
            value={config}
            onChange={(next) => setConfig({ ...config, ...next })}
            toolsets={toolsets}
            toolsLoading={toolsLoading}
            toolsError={toolsError}
            providers={providers}
            disabled={busy}
          />
        )}

        {config && (
          <div className="guided-prompt">
            <button
              type="button"
              className="provider-form__prompt-button"
              onClick={() => setPromptOpen((open) => !open)}
              aria-expanded={promptOpen}
            >
              {promptOpen ? "Hide system prompt" : "Edit system prompt"}
            </button>
            {promptOpen && (
              <label className="field tool-config__constraints">
                <span>System prompt</span>
                <textarea
                  rows={5}
                  disabled={busy}
                  value={config.systemPrompt}
                  onChange={(e) => setConfig({ ...config, systemPrompt: e.target.value })}
                />
                <span className="provider-form__hint">
                  Sent as the system message at the start of every turn. Edits are saved in this
                  browser.
                </span>
              </label>
            )}
          </div>
        )}
      </section>

      {activeTurn && reviewEntries.length > 0 && (
        <ReviewPanel jobId={activeTurn.jobId} entries={reviewEntries} submit={submitReview} />
      )}

      <ChatPanel
        messages={messages}
        draft={draft}
        setDraft={setDraft}
        busy={busy}
        activity={activeTurn?.status?.activity ?? null}
        canSend={canSend}
        error={error}
        onSend={sendMessage}
        onStop={stopTurn}
        onClear={clearChat}
      />
    </div>
  );
}

interface ChatPanelProps {
  messages: { id: string; role: "user" | "assistant"; content: string }[];
  draft: string;
  setDraft: (draft: string) => void;
  busy: boolean;
  activity: string | null;
  canSend: boolean;
  error: string | null;
  onSend: () => void;
  onStop: () => void;
  onClear: () => void;
}

function ChatPanel({
  messages,
  draft,
  setDraft,
  busy,
  activity,
  canSend,
  error,
  onSend,
  onStop,
  onClear,
}: ChatPanelProps) {
  const listRef = useRef<HTMLDivElement | null>(null);

  // Keep the latest message (and the activity indicator) in view.
  useEffect(() => {
    const node = listRef.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [messages, busy, activity]);

  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    // Enter sends; Shift+Enter inserts a newline.
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (canSend) onSend();
    }
  }

  return (
    <section className="panel chat">
      <div className="panel__title chat__head">
        <span>Conversation</span>
        <button type="button" disabled={busy || messages.length === 0} onClick={onClear}>
          Clear chat
        </button>
      </div>

      <div className="chat__messages" ref={listRef}>
        {messages.length === 0 && (
          <div className="muted">
            Ask a question, or send a result from the Analysis Queue to start the conversation.
          </div>
        )}
        {messages.map((message) => (
          <div key={message.id} className={`chat__message chat__message--${message.role}`}>
            <span className="chat__role">{message.role === "user" ? "You" : "Assistant"}</span>
            <div className="chat__bubble">{message.content}</div>
          </div>
        ))}
        {busy && (
          <div className="chat__message chat__message--assistant">
            <span className="chat__role">Assistant</span>
            <div className="chat__bubble chat__bubble--pending">
              <Loading label={activity ?? "thinking"} />
            </div>
          </div>
        )}
      </div>

      {error && <ErrorBanner message={error} />}

      <div className="chat__input">
        <textarea
          rows={3}
          value={draft}
          disabled={busy}
          placeholder="Message the analysis agent… (Enter to send, Shift+Enter for a new line)"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <div className="chat__actions">
          <button type="button" className="launch__button" disabled={!canSend} onClick={onSend}>
            Send
          </button>
          {busy && (
            <button
              type="button"
              className="launch__button launch__button--danger"
              onClick={onStop}
            >
              Stop
            </button>
          )}
        </div>
      </div>
    </section>
  );
}
