import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { ApiError } from "../api/client";
import { cancelGuidedTurn, getGuidedTurn, startGuidedTurn, submitGuidedReview } from "../api/guided";
import { getMcpTools } from "../api/pentest";
import { getProviders } from "../api/plans";
import type {
  GuidedChatRole,
  GuidedTurnStatus,
  McpToolsetInfo,
  PendingReview,
  ProviderOption,
} from "../api/types";
import {
  buildToolConfig,
  defaultAllowedTools,
  seedGuidedConfig,
} from "../components/attack/pentestConfig";
import {
  GUIDED_ANALYSIS_CHAT_KEY,
  GUIDED_ANALYSIS_CONFIG_KEY,
  reconcileConfig,
} from "../components/attack/persistedConfig";
import type { GuidedUiConfig } from "../components/attack/types";
import { useFetch } from "../lib/useFetch";
import { usePersistedState } from "../lib/usePersistedState";
import { readJson, writeJson } from "../lib/storage";

const POLL_INTERVAL_MS = 1500;

/** One message in the visible conversation (final content only, no tool rounds). */
export interface ChatMessage {
  id: string;
  role: GuidedChatRole;
  content: string;
  /** For assistant messages: the turn (job) that produced it, so the "Tool script"
   *  button can fetch this turn's recorded tool use. Absent on user messages. */
  turnJobId?: string;
}

/** The in-flight turn: its job id and latest polled status (null until first poll). */
export interface ActiveTurn {
  jobId: string;
  status: GuidedTurnStatus | null;
}

interface GuidedAnalysisValue {
  config: GuidedUiConfig | null;
  setConfig: (config: GuidedUiConfig) => void;
  /** Discard the saved config and re-seed from provider/tool defaults. */
  resetConfig: () => void;
  providers: ProviderOption[] | undefined;
  providersError: string | null;
  toolsets: McpToolsetInfo[] | undefined;
  toolsLoading: boolean;
  toolsError: string | null;
  messages: ChatMessage[];
  /** Ordered job ids of the chat's completed turns, for the "Tool script" button. */
  turnJobIds: string[];
  draft: string;
  setDraft: (draft: string) => void;
  /** Append text to the chat input (used by "Send to Guided Analysis"). */
  stageInput: (text: string) => void;
  activeTurn: ActiveTurn | null;
  /** True from the moment a turn is sent until it ends — covers the start
   *  window before a job id exists, so the UI shows progress and a Stop button
   *  immediately (not only once the backend has accepted the turn). */
  busy: boolean;
  /** Error from the last turn (cleared when a new turn starts). */
  error: string | null;
  /** Send the current draft as a new user turn (no-op when empty or busy). */
  sendMessage: () => void;
  /** Resolve a parked tool review for the active turn. */
  submitReview: typeof submitGuidedReview;
  /** Cancel the in-flight turn (and kill its MCP tools). Works during the start
   *  window too: the turn is cancelled as soon as its job id arrives. */
  stopTurn: () => void;
  /** Clear the conversation (disabled while a turn is in flight). */
  clearChat: () => void;
}

/** Chat state mirrored to the browser so the conversation survives a refresh. */
interface ChatSnapshot {
  messages: ChatMessage[];
  draft: string;
  /** A turn that was in flight at save time, so a refresh can reattach polling. */
  activeJobId: string | null;
}

const GuidedAnalysisContext = createContext<GuidedAnalysisValue | null>(null);

let messageIdCounter = 0;
function nextMessageId(): string {
  messageIdCounter += 1;
  return `m${messageIdCounter}-${Date.now()}`;
}

export function GuidedAnalysisProvider({ children }: { children: ReactNode }) {
  const providers = useFetch(() => getProviders(), []);
  const tools = useFetch(() => getMcpTools(), []);

  // Restored chat snapshot, read once so the lazy initializers below agree.
  const restoredRef = useRef<ChatSnapshot | null | undefined>(undefined);
  const getRestored = (): ChatSnapshot | null => {
    if (restoredRef.current === undefined) {
      restoredRef.current = readJson<ChatSnapshot>(GUIDED_ANALYSIS_CHAT_KEY);
    }
    return restoredRef.current;
  };

  const [messages, setMessages] = useState<ChatMessage[]>(() => getRestored()?.messages ?? []);
  const [draft, setDraft] = useState<string>(() => getRestored()?.draft ?? "");
  const [activeTurn, setActiveTurn] = useState<ActiveTurn | null>(() => {
    const jobId = getRestored()?.activeJobId;
    return jobId ? { jobId, status: null } : null;
  });
  const [error, setError] = useState<string | null>(null);
  // True while the start request is in flight (before a job id exists). Combined
  // with `activeTurn` it drives the `busy` flag the UI uses for progress + Stop.
  const [starting, setStarting] = useState(false);
  // Set when the user hits Stop during the start window; honoured as soon as the
  // job id arrives so a turn never keeps running after a Stop.
  const cancelRequestedRef = useRef(false);

  const [config, setConfig, { hydrated: configHydrated, clear: clearStoredConfig }] =
    usePersistedState<GuidedUiConfig>(GUIDED_ANALYSIS_CONFIG_KEY);
  const toolsSeeded = useRef(configHydrated);
  const configReconciled = useRef(false);

  // Advance the message id counter past any restored message so new ids are unique.
  useEffect(() => {
    const restored = restoredRef.current?.messages ?? [];
    for (const message of restored) {
      const n = Number(/^m(\d+)-/.exec(message.id)?.[1]);
      if (Number.isFinite(n)) messageIdCounter = Math.max(messageIdCounter, n);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Mirror the chat to the browser (the per-turn polled status is not persisted;
  // the poll refills it on resume).
  useEffect(() => {
    writeJson(GUIDED_ANALYSIS_CHAT_KEY, {
      messages,
      draft,
      activeJobId: activeTurn?.jobId ?? null,
    } satisfies ChatSnapshot);
  }, [messages, draft, activeTurn]);

  // Seed the config once providers load, then conservative tool defaults — mirrors
  // the Analysis Queue's seeding so both tabs start from the same defaults.
  useEffect(() => {
    if (config || !providers.data) return;
    const provider = providers.data.providers[0];
    if (!provider) return;
    setConfig(seedGuidedConfig(provider));
  }, [config, providers.data, setConfig]);

  useEffect(() => {
    if (!config || !tools.data || toolsSeeded.current) return;
    toolsSeeded.current = true;
    const defaults = defaultAllowedTools(tools.data.toolsets);
    setConfig((prev) => (prev ? { ...prev, allowedTools: defaults } : prev));
  }, [config, tools.data, setConfig]);

  useEffect(() => {
    if (!providers.data || configReconciled.current) return;
    configReconciled.current = true;
    const list = providers.data.providers;
    setConfig((prev) => (prev ? reconcileConfig(prev, list) : prev));
  }, [providers.data, setConfig]);

  // Poll the in-flight turn; append the reply (or surface an error) when it ends.
  useEffect(() => {
    if (!activeTurn) return;
    const jobId = activeTurn.jobId;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const finish = (assistant: string | null, failure: string | null) => {
      if (assistant && assistant.trim()) {
        setMessages((prev) => [
          ...prev,
          { id: nextMessageId(), role: "assistant", content: assistant, turnJobId: jobId },
        ]);
      }
      if (failure) setError(failure);
      setActiveTurn(null);
    };

    const run = async () => {
      let status: GuidedTurnStatus;
      try {
        status = await getGuidedTurn(jobId);
      } catch (err) {
        if (cancelled) return;
        // A 404 means the backend lost the turn (it restarted); stop polling.
        if (err instanceof ApiError && err.status === 404) {
          finish(null, "Turn no longer available (backend restarted).");
          return;
        }
        // Transient error: retry next tick.
        timer = setTimeout(run, POLL_INTERVAL_MS);
        return;
      }
      if (cancelled) return;

      if (status.status === "running") {
        setActiveTurn({ jobId, status });
        timer = setTimeout(run, POLL_INTERVAL_MS);
        return;
      }
      if (status.status === "done") finish(status.content, null);
      else if (status.status === "error") finish(null, status.error ?? "The turn failed.");
      else finish(null, null); // cancelled — leave the conversation as-is
    };

    void run();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeTurn?.jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  const stageInput = useCallback((text: string) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    setDraft((prev) => (prev.trim() ? `${prev.trimEnd()}\n\n${trimmed}` : trimmed));
  }, []);

  const sendMessage = useCallback(() => {
    if (!config || activeTurn || starting) return;
    const content = draft.trim();
    if (!content) return;

    const userMessage: ChatMessage = { id: nextMessageId(), role: "user", content };
    const history = [...messages, userMessage];
    setMessages(history);
    setDraft("");
    setError(null);
    cancelRequestedRef.current = false;
    setStarting(true);

    startGuidedTurn({
      provider: config.agent.provider,
      model: config.agent.model || null,
      reasoning_effort: config.agent.reasoningEffort || null,
      max_iterations: config.agent.maxIterations,
      system_prompt: config.systemPrompt,
      messages: history.map(({ role, content }) => ({ role, content })),
      tool_config: buildToolConfig(config),
    })
      .then((response) => {
        // Stop pressed before the job id arrived: cancel it now, don't poll.
        if (cancelRequestedRef.current) {
          cancelGuidedTurn(response.job_id).catch(() => {});
          return;
        }
        setActiveTurn({ jobId: response.job_id, status: null });
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setStarting(false));
  }, [config, activeTurn, starting, draft, messages]);

  const stopTurn = useCallback(() => {
    cancelRequestedRef.current = true; // honoured in the start handler if no id yet
    if (activeTurn) {
      cancelGuidedTurn(activeTurn.jobId).catch(() => {
        /* best-effort: the poll still observes the terminal status */
      });
    }
  }, [activeTurn]);

  const clearChat = useCallback(() => {
    if (activeTurn || starting) return;
    setMessages([]);
    setError(null);
  }, [activeTurn, starting]);

  const resetConfig = useCallback(() => {
    clearStoredConfig();
    const provider = providers.data?.providers[0];
    if (!provider) {
      setConfig(null);
      toolsSeeded.current = false;
      return;
    }
    const seeded = seedGuidedConfig(provider);
    const toolsReady = tools.data != null;
    setConfig({
      ...seeded,
      allowedTools: toolsReady ? defaultAllowedTools(tools.data!.toolsets) : [],
    });
    toolsSeeded.current = toolsReady;
    configReconciled.current = true;
  }, [providers.data, tools.data, clearStoredConfig, setConfig]);

  const value: GuidedAnalysisValue = {
    config,
    setConfig,
    resetConfig,
    providers: providers.data?.providers,
    providersError: providers.error,
    toolsets: tools.data?.toolsets,
    toolsLoading: tools.loading,
    toolsError: tools.error,
    messages,
    turnJobIds: messages.flatMap((m) => (m.turnJobId ? [m.turnJobId] : [])),
    draft,
    setDraft,
    stageInput,
    activeTurn,
    busy: starting || activeTurn !== null,
    error,
    sendMessage,
    submitReview: submitGuidedReview,
    stopTurn,
    clearChat,
  };

  return (
    <GuidedAnalysisContext.Provider value={value}>{children}</GuidedAnalysisContext.Provider>
  );
}

export function useGuidedAnalysis(): GuidedAnalysisValue {
  const value = useContext(GuidedAnalysisContext);
  if (!value) {
    throw new Error("useGuidedAnalysis must be used within a GuidedAnalysisProvider");
  }
  return value;
}

/** Pending tool reviews for the active turn, shaped for the shared ReviewPanel. */
export function turnReviews(active: ActiveTurn | null): PendingReview[] {
  return active?.status?.pending_reviews ?? [];
}
