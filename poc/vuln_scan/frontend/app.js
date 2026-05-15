const ANALYSIS_TYPES = [
  {
    label: "Recon: Domain",
    description: "Perform a security analysis and discovery of all domains mentioned in the event.",
  },
  {
    label: "Recon: Ports",
    description: "Perform extensive port scans on the machines mentioned in the event.",
  },
  {
    label: "Recon: HTTP Path/API",
    description: "Perform discovery on any HTTP API or path found in the event.",
  },
  {
    label: "Authentication",
    description: "Evaluate authentication, session, authorization, and access-control behavior in the event.",
  },
  {
    label: "Configuration",
    description: "Evaluate endpoint/cloud configuration of all remote endpoints in the event. Look for HTTP configuration, exposed storage/database, exposed secrets, etc.",
  },
];
const DEFAULT_ANALYSIS_TYPE = ANALYSIS_TYPES[0].label;
const ACTIVE_ANALYSIS_STATUSES = new Set(["queued", "running", "waiting_for_tool_approval"]);

const state = {
  events: [],
  selectedEventId: null,
  providers: [],
  selectedProvider: null,
  selectedModel: null,
  appDetailsFileName: "",
  appDetailsContent: null,
  userIntendFileName: "",
  userIntendContent: null,
  runningEventIds: new Set(),
  results: {},
  configError: null,
  activeTab: "phase1",
  analysisItems: [],
  nextAnalysisItemId: 1,
  analysisConstraints: "",
  autoApproveMcpDatabaseRequests: false,
  autoApproveAllMcpRequests: false,
  phase2RunId: null,
  phase2Run: null,
  phase2PollTimer: null,
};

const eventList = document.querySelector("#eventList");
const eventCount = document.querySelector("#eventCount");
const selectedEvent = document.querySelector("#selectedEvent");
const statusLine = document.querySelector("#statusLine");
const report = document.querySelector("#report");
const startButton = document.querySelector("#startButton");
const refreshButton = document.querySelector("#refreshButton");
const configText = document.querySelector("#configText");
const providerSelect = document.querySelector("#providerSelect");
const modelSelect = document.querySelector("#modelSelect");
const appDetailsBrowseButton = document.querySelector("#appDetailsBrowseButton");
const appDetailsFileInput = document.querySelector("#appDetailsFileInput");
const appDetailsFileName = document.querySelector("#appDetailsFileName");
const userIntendBrowseButton = document.querySelector("#userIntendBrowseButton");
const userIntendFileInput = document.querySelector("#userIntendFileInput");
const userIntendFileName = document.querySelector("#userIntendFileName");
const phaseOneTab = document.querySelector("#phaseOneTab");
const vulnerabilityTab = document.querySelector("#vulnerabilityTab");
const phaseOnePanel = document.querySelector("#phaseOnePanel");
const vulnerabilityPanel = document.querySelector("#vulnerabilityPanel");
const addAnalysisButton = document.querySelector("#addAnalysisButton");
const startAnalysisButton = document.querySelector("#startAnalysisButton");
const abortAnalysisButton = document.querySelector("#abortAnalysisButton");
const stopToolButton = document.querySelector("#stopToolButton");
const autoApproveMcpDatabaseRequests = document.querySelector("#autoApproveMcpDatabaseRequests");
const autoApproveAllMcpRequests = document.querySelector("#autoApproveAllMcpRequests");
const analysisItems = document.querySelector("#analysisItems");
const constraintsInput = document.querySelector("#constraintsInput");
const analysisStatus = document.querySelector("#analysisStatus");
const analysisProcess = document.querySelector("#analysisProcess");
const analysisProcessText = document.querySelector("#analysisProcessText");
const toolApprovals = document.querySelector("#toolApprovals");
const analysisProgress = document.querySelector("#analysisProgress");

refreshButton.addEventListener("click", loadEvents);
startButton.addEventListener("click", startPhaseOne);
phaseOneTab.addEventListener("click", () => setActiveTab("phase1"));
vulnerabilityTab.addEventListener("click", () => setActiveTab("phase2"));
addAnalysisButton.addEventListener("click", addAnalysisItem);
startAnalysisButton.addEventListener("click", startPhaseTwo);
abortAnalysisButton.addEventListener("click", abortPhaseTwo);
stopToolButton.addEventListener("click", stopActiveTool);
autoApproveMcpDatabaseRequests.addEventListener("change", () => {
  state.autoApproveMcpDatabaseRequests = autoApproveMcpDatabaseRequests.checked;
  renderPhaseTwo();
});
autoApproveAllMcpRequests.addEventListener("change", () => {
  state.autoApproveAllMcpRequests = autoApproveAllMcpRequests.checked;
  renderPhaseTwo();
});
constraintsInput.addEventListener("input", () => {
  state.analysisConstraints = constraintsInput.value;
  renderPhaseTwo();
});
providerSelect.addEventListener("change", () => {
  state.selectedProvider = providerSelect.value;
  state.selectedModel = modelsForProvider(state.selectedProvider)[0] || "";
  renderConfig();
});
modelSelect.addEventListener("change", () => {
  state.selectedModel = modelSelect.value;
  renderConfig();
});
appDetailsBrowseButton.addEventListener("click", () => appDetailsFileInput.click());
userIntendBrowseButton.addEventListener("click", () => userIntendFileInput.click());
appDetailsFileInput.addEventListener("change", () => readSelectedFile(appDetailsFileInput, "appDetails"));
userIntendFileInput.addEventListener("change", () => readSelectedFile(userIntendFileInput, "userIntend"));

loadConfig();
loadEvents();
loadPrescans();

async function loadConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const config = await response.json();
    state.configError = null;
    state.providers = Array.isArray(config.providers) ? config.providers : [];
    state.selectedProvider = config.provider || firstAvailableProvider()?.id || null;
    state.selectedModel = config.model || modelsForProvider(state.selectedProvider)[0] || null;
    state.appDetailsFileName = "";
    state.appDetailsContent = null;
    state.userIntendFileName = "";
    state.userIntendContent = null;
    renderConfig();
  } catch (error) {
    state.providers = [];
    state.selectedProvider = null;
    state.selectedModel = null;
    state.appDetailsFileName = "";
    state.appDetailsContent = null;
    state.userIntendFileName = "";
    state.userIntendContent = null;
    state.configError = "Backend configuration unavailable.";
    renderConfig();
  }
  renderEvents();
}

async function loadEvents() {
  setStatus("Loading events...");
  try {
    const response = await fetch("/api/events");
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    state.events = await response.json();
    if (!state.events.some((event) => event.event_id === state.selectedEventId)) {
      state.selectedEventId = state.events[0]?.event_id ?? null;
    }
    renderEvents();
    renderSelectedEvent();
    setStatus(state.events.length ? "Select an event and evaluate it." : "No events found.");
  } catch (error) {
    setStatus(`Could not load events: ${error.message}`, true);
  }
}

async function loadPrescans() {
  try {
    const response = await fetch("/api/prescans");
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    const prescans = await response.json();
    state.results = {};
    for (const prescan of prescans) {
      state.results[prescan.event_id] = {
        event_id: prescan.event_id,
        recording_id: prescan.recording_id,
        markdown: markdownFromSummary(prescan),
        summary: prescan,
      };
    }
    renderEvents();
    renderSelectedEvent();
  } catch (error) {
    setStatus(`Could not load stored evaluations: ${error.message}`, true);
  }
}

async function startPhaseOne() {
  const event = selected();
  if (!event || isEventRunning(event.event_id)) {
    return;
  }

  state.runningEventIds.add(event.event_id);
  renderConfig();
  renderEvents();
  renderSelectedEvent();
  setStatus(`Evaluating event ${event.event_id} with ${providerLabel(state.selectedProvider)} ${state.selectedModel}...`);

  try {
    const payload = {
      event_id: event.event_id,
      provider: state.selectedProvider,
      model: state.selectedModel,
      ...contextPayload(),
    };
    const response = await fetch("/api/phase1", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    const result = await response.json();
    state.results[event.event_id] = result;
    renderSelectedEvent();
    setStatus(`Evaluation complete for event ${event.event_id}.`);
  } catch (error) {
    setStatus(`Evaluation failed for event ${event.event_id}: ${error.message}`, true);
  } finally {
    state.runningEventIds.delete(event.event_id);
    renderConfig();
    renderEvents();
    renderSelectedEvent();
  }
}

async function startPhaseTwo() {
  const event = selected();
  if (!event || isPhaseTwoRunning()) {
    return;
  }

  const payload = {
    event_id: event.event_id,
    analysis_types: state.analysisItems.map((item) => item.type),
    constraints: state.analysisConstraints,
    auto_approve_mcp_database_requests: state.autoApproveMcpDatabaseRequests,
    auto_approve_all_mcp_requests: state.autoApproveAllMcpRequests,
    provider: state.selectedProvider,
    model: state.selectedModel,
    ...contextPayload(),
  };

  setAnalysisStatus(`Starting vulnerability analysis for event ${event.event_id}...`);
  try {
    const response = await fetch("/api/phase2", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    state.phase2Run = await response.json();
    state.phase2RunId = state.phase2Run.run_id;
    renderPhaseTwo();
    schedulePhaseTwoPolling();
  } catch (error) {
    setAnalysisStatus(`Vulnerability analysis failed to start: ${error.message}`, true);
  }
}

async function abortPhaseTwo() {
  if (!state.phase2RunId) {
    return;
  }
  try {
    const response = await fetch(`/api/phase2/${state.phase2RunId}/abort`, {method: "POST"});
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    state.phase2Run = await response.json();
    renderPhaseTwo();
    stopPhaseTwoPolling();
  } catch (error) {
    setAnalysisStatus(`Abort failed: ${error.message}`, true);
  }
}

async function stopActiveTool() {
  if (!state.phase2RunId || !canStopActiveTool()) {
    return;
  }
  try {
    const response = await fetch(`/api/phase2/${state.phase2RunId}/tool/stop`, {method: "POST"});
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    state.phase2Run = await response.json();
    renderPhaseTwo();
  } catch (error) {
    setAnalysisStatus(`Stop tool failed: ${error.message}`, true);
  }
}

async function decideToolRequest(requestId, approved) {
  if (!state.phase2RunId) {
    return;
  }
  try {
    const response = await fetch(`/api/phase2/${state.phase2RunId}/tool-requests/${requestId}/decision`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({approved}),
    });
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    state.phase2Run = await response.json();
    renderPhaseTwo();
  } catch (error) {
    setAnalysisStatus(`Tool decision failed: ${error.message}`, true);
  }
}

function schedulePhaseTwoPolling() {
  stopPhaseTwoPolling();
  state.phase2PollTimer = window.setInterval(refreshPhaseTwoRun, 1500);
  refreshPhaseTwoRun();
}

function stopPhaseTwoPolling() {
  if (state.phase2PollTimer) {
    window.clearInterval(state.phase2PollTimer);
    state.phase2PollTimer = null;
  }
}

async function refreshPhaseTwoRun() {
  if (!state.phase2RunId) {
    stopPhaseTwoPolling();
    return;
  }
  try {
    const response = await fetch(`/api/phase2/${state.phase2RunId}`);
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    state.phase2Run = await response.json();
    renderPhaseTwo();
    if (!isPhaseTwoRunning()) {
      stopPhaseTwoPolling();
    }
  } catch (error) {
    setAnalysisStatus(`Could not refresh analysis: ${error.message}`, true);
    stopPhaseTwoPolling();
  }
}

function setActiveTab(tab) {
  state.activeTab = tab;
  const phaseOneActive = tab === "phase1";
  phaseOneTab.classList.toggle("active", phaseOneActive);
  vulnerabilityTab.classList.toggle("active", !phaseOneActive);
  phaseOneTab.setAttribute("aria-selected", String(phaseOneActive));
  vulnerabilityTab.setAttribute("aria-selected", String(!phaseOneActive));
  phaseOnePanel.classList.toggle("active", phaseOneActive);
  vulnerabilityPanel.classList.toggle("active", !phaseOneActive);
}

function addAnalysisItem() {
  if (state.analysisItems.length > 0) {
    setAnalysisStatus("Only one vulnerability analysis type can be selected.");
    return;
  }
  state.analysisItems.push({
    id: state.nextAnalysisItemId++,
    type: DEFAULT_ANALYSIS_TYPE,
  });
  renderPhaseTwo();
}

async function readSelectedFile(input, target) {
  const file = input.files?.[0];
  if (!file) {
    return;
  }

  try {
    const content = await file.text();
    if (target === "appDetails") {
      state.appDetailsFileName = file.name;
      state.appDetailsContent = content;
    } else {
      state.userIntendFileName = file.name;
      state.userIntendContent = content;
    }
    renderConfig();
    setStatus(`Loaded ${file.name}.`);
  } catch (error) {
    setStatus(`Could not read ${file.name}: ${error.message}`, true);
  } finally {
    input.value = "";
  }
}

function contextPayload() {
  const payload = {};

  if (state.appDetailsContent !== null) {
    payload.app_details_content = state.appDetailsContent;
  }
  if (state.userIntendContent !== null) {
    payload.user_intend_content = state.userIntendContent;
  }
  return payload;
}

function renderConfig() {
  const availableProviders = state.providers.filter((provider) => provider.available);

  providerSelect.innerHTML = "";
  for (const provider of availableProviders) {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = provider.has_api_key ? `${provider.label} (key configured)` : provider.label;
    providerSelect.append(option);
  }

  if (!availableProviders.some((provider) => provider.id === state.selectedProvider)) {
    state.selectedProvider = availableProviders[0]?.id || null;
  }

  const models = modelsForProvider(state.selectedProvider);
  if (!models.includes(state.selectedModel)) {
    state.selectedModel = models[0] || null;
  }

  modelSelect.innerHTML = "";
  for (const model of models) {
    const option = document.createElement("option");
    option.value = model;
    option.textContent = model;
    modelSelect.append(option);
  }

  providerSelect.value = state.selectedProvider || "";
  modelSelect.value = state.selectedModel || "";
  appDetailsFileName.textContent = state.appDetailsFileName || "Using configured default";
  userIntendFileName.textContent = state.userIntendFileName || "Using configured default";
  providerSelect.disabled = availableProviders.length === 0;
  modelSelect.disabled = models.length === 0;

  if (state.configError) {
    configText.textContent = state.configError;
    renderSelectedEvent();
    return;
  }

  const missingProviders = state.providers
    .filter((provider) => !provider.available)
    .map((provider) => provider.label);
  const selectedText = state.selectedProvider && state.selectedModel
    ? `Using ${providerLabel(state.selectedProvider)} with ${state.selectedModel}`
    : "No LLM provider is available.";
  configText.textContent = missingProviders.length
    ? `${selectedText}. Additional providers need keys: ${missingProviders.join(", ")}.`
    : selectedText;
  renderSelectedEvent();
}

function renderEvents() {
  eventList.innerHTML = "";
  eventCount.textContent = `${state.events.length}`;

  for (const event of state.events) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `event-row${event.event_id === state.selectedEventId ? " selected" : ""}`;
    button.addEventListener("click", () => {
      state.selectedEventId = event.event_id;
      renderEvents();
      renderSelectedEvent();
      setStatus("Ready.");
    });

    const title = document.createElement("div");
    title.className = "event-title";

    const description = document.createElement("div");
    description.className = "event-description";
    description.textContent = event.description || "(no description)";

    const id = document.createElement("div");
    id.className = "event-id";
    id.textContent = `#${event.event_id}`;

    title.append(description, id);

    const meta = document.createElement("div");
    meta.className = "event-meta";
    const recordings = event.recording_ids.length ? event.recording_ids.join(", ") : "unknown";
    const evaluationState = isEventRunning(event.event_id)
      ? "evaluating"
      : state.results[event.event_id]
        ? "evaluated"
        : "not evaluated";
    meta.textContent = `${event.packet_count} packets, recordings ${recordings}, ${evaluationState}`;

    button.append(title, meta);
    eventList.append(button);
  }

  renderSelectedEvent();
}

function renderSelectedEvent() {
  const event = selected();
  const isRunning = event ? isEventRunning(event.event_id) : false;
  startButton.textContent = isRunning ? "Evaluating..." : "Evaluate";
  startButton.disabled = isRunning || !event || !state.selectedProvider || !state.selectedModel;
  selectedEvent.textContent = event
    ? `Selected event ${event.event_id}: ${event.description || "(no description)"}`
    : "Select an event.";

  if (!event) {
    report.textContent = "";
    renderPhaseTwo();
    return;
  }
  if (isRunning) {
    report.textContent = `Evaluation is running for event ${event.event_id}.`;
    renderPhaseTwo();
    return;
  }
  const result = state.results[event.event_id];
  report.textContent = result?.markdown || "No stored evaluation for this event.";
  renderPhaseTwo();
}

function renderPhaseTwo() {
  constraintsInput.value = state.analysisConstraints;
  const running = isPhaseTwoRunning();
  autoApproveMcpDatabaseRequests.checked = state.autoApproveMcpDatabaseRequests || state.autoApproveAllMcpRequests;
  autoApproveMcpDatabaseRequests.disabled = running || state.autoApproveAllMcpRequests;
  autoApproveAllMcpRequests.checked = state.autoApproveAllMcpRequests;
  autoApproveAllMcpRequests.disabled = running;
  renderAnalysisItems();

  const event = selected();
  addAnalysisButton.disabled = running || state.analysisItems.length >= 1;
  startAnalysisButton.disabled = running || !event || !state.selectedProvider || !state.selectedModel || state.analysisItems.length === 0;
  abortAnalysisButton.disabled = !running;
  stopToolButton.disabled = !canStopActiveTool();

  if (!event) {
    setAnalysisStatus("Select an event before starting vulnerability analysis.");
  } else if (running && state.phase2Run) {
    setAnalysisStatus(`Analysis ${state.phase2Run.status} for event ${state.phase2Run.event_id}.`);
  } else if (state.phase2Run?.status === "completed") {
    setAnalysisStatus(`Analysis complete for event ${state.phase2Run.event_id}.`);
  } else if (state.phase2Run?.status === "failed") {
    setAnalysisStatus(`Analysis failed: ${state.phase2Run.error || "unknown error"}`, true);
  } else if (state.phase2Run?.status === "aborted") {
    setAnalysisStatus("Analysis aborted.");
  } else if (state.analysisItems.length === 0) {
    setAnalysisStatus("Select a vulnerability analysis type.");
  } else {
    setAnalysisStatus("Ready to start vulnerability analysis.");
  }

  renderToolApprovals();
  renderAnalysisProcess();
  renderAnalysisProgress();
}

function renderAnalysisItems() {
  analysisItems.innerHTML = "";
  if (state.analysisItems.length === 0) {
    const empty = document.createElement("div");
    empty.className = "event-meta";
    empty.textContent = "No analysis type selected.";
    analysisItems.append(empty);
    return;
  }

  for (const item of state.analysisItems) {
    const row = document.createElement("div");
    row.className = "analysis-item";

    const label = document.createElement("label");
    const caption = document.createElement("span");
    caption.textContent = "Type";
    const select = document.createElement("select");
    for (const type of ANALYSIS_TYPES) {
      const option = document.createElement("option");
      option.value = type.label;
      option.textContent = type.label;
      select.append(option);
    }
    select.value = item.type;
    select.disabled = isPhaseTwoRunning();
    select.addEventListener("change", () => {
      item.type = select.value;
      renderPhaseTwo();
    });
    label.append(caption, select);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove";
    remove.disabled = isPhaseTwoRunning();
    remove.addEventListener("click", () => {
      state.analysisItems = state.analysisItems.filter((candidate) => candidate.id !== item.id);
      renderPhaseTwo();
    });

    row.append(label, remove);
    analysisItems.append(row);
  }
}

function renderToolApprovals() {
  toolApprovals.innerHTML = "";
  const pending = state.phase2Run?.pending_tool_requests || [];
  for (const request of pending) {
    const card = document.createElement("div");
    card.className = "tool-approval";

    const title = document.createElement("div");
    title.className = "tool-approval-title";
    title.textContent = `Tool permission request ${request.request_id}`;

    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(request.tool_call, null, 2);

    const actions = document.createElement("div");
    actions.className = "tool-approval-actions";

    const deny = document.createElement("button");
    deny.type = "button";
    deny.textContent = "Deny";
    deny.addEventListener("click", () => decideToolRequest(request.request_id, false));

    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = "Approve";
    approve.addEventListener("click", () => decideToolRequest(request.request_id, true));

    actions.append(deny, approve);
    card.append(title, pre, actions);
    toolApprovals.append(card);
  }
}

function renderAnalysisProgress() {
  const run = state.phase2Run;
  if (!run) {
    analysisProgress.textContent = "No vulnerability analysis run yet.";
    return;
  }

  const lines = [
    `Run: ${run.run_id}`,
    `Status: ${run.status}`,
    `Event: ${run.event_id}`,
    `Types: ${(run.analysis_types || []).join(", ") || "(none)"}`,
    "",
    "Progress:",
  ];
  for (const item of run.progress || []) {
    lines.push(`[${formatTime(item.timestamp)}] ${item.message}`);
  }
  if (run.result_markdown) {
    lines.push("", "Result:", run.result_markdown);
  }
  if (run.error) {
    lines.push("", `Error: ${run.error}`);
  }
  analysisProgress.textContent = lines.join("\n");
}

function renderAnalysisProcess() {
  const process = currentAnalysisProcess();
  analysisProcessText.textContent = process.label;
  analysisProcess.classList.toggle("active", process.active);
  analysisProcess.classList.toggle("terminal", process.terminal);
  analysisProcess.classList.toggle("error", process.error);
}

function currentAnalysisProcess() {
  const run = state.phase2Run;
  if (!run) {
    return {label: "Idle", active: false, terminal: false, error: false};
  }

  if (run.status === "completed") {
    return {label: "Analysis complete", active: false, terminal: true, error: false};
  }
  if (run.status === "failed") {
    return {label: `Analysis failed: ${run.error || "unknown error"}`, active: false, terminal: true, error: true};
  }
  if (run.status === "aborted") {
    return {label: "Analysis aborted", active: false, terminal: true, error: false};
  }
  if (run.status === "queued") {
    return {label: "Queued", active: true, terminal: false, error: false};
  }

  const activeTool = run.active_tool_execution;
  if (activeTool?.status === "stop_requested") {
    return {label: `Stopping MCP tool: ${toolDisplayName(activeTool.tool_call)}`, active: true, terminal: false, error: false};
  }
  if (activeTool?.status === "running") {
    return {label: `MCP tool running: ${toolDisplayName(activeTool.tool_call)}`, active: true, terminal: false, error: false};
  }

  const pending = run.pending_tool_requests || [];
  if (pending.length > 0) {
    const toolName = toolDisplayName(pending[0].tool_call);
    return {label: `Awaiting approval: ${toolName}`, active: true, terminal: false, error: false};
  }

  const latestMessage = latestProgressMessage(run);
  return {
    label: processLabelFromProgress(latestMessage, run.status),
    active: isPhaseTwoRunning(),
    terminal: false,
    error: false,
  };
}

function latestProgressMessage(run) {
  const progress = Array.isArray(run.progress) ? run.progress : [];
  return progress[progress.length - 1]?.message || "";
}

function processLabelFromProgress(message, status) {
  const runningTool = /^Running approved tool\s+(.+)\.$/.exec(message);
  if (runningTool) {
    return `MCP tool running: ${runningTool[1]}`;
  }

  const awaitingTool = /^Awaiting approval for tool\s+(.+)\.$/.exec(message);
  if (awaitingTool) {
    return `Awaiting approval: ${awaitingTool[1]}`;
  }

  const requestedTool = /^LLM requested tool\s+(.+)\.$/.exec(message);
  if (requestedTool) {
    return `Preparing MCP tool: ${requestedTool[1]}`;
  }

  if (message === "Prompt prepared; invoking LLM vulnerability analysis.") {
    return "LLM thinking";
  }
  if (message.startsWith("Connecting MCP server") || message.includes("loaded") || message.startsWith("Phase-two analysis has access")) {
    return "Preparing MCP tools";
  }
  if (message.startsWith("Loading packet context") || message === "Loaded stored phase-one summary.") {
    return "Loading packet context";
  }
  if (message.startsWith("MCP database tool request auto-approved")) {
    return "MCP database request auto-approved";
  }
  if (message.startsWith("MCP tool request auto-approved")) {
    return "MCP request auto-approved";
  }
  if (message.startsWith("MCP tool stop requested")) {
    return "Stopping MCP tool";
  }
  if (message.startsWith("MCP tool stopped by user")) {
    return "MCP tool stopped by user";
  }
  if (message.startsWith("Tool request approved")) {
    return "Tool approved; resuming analysis";
  }
  if (message.startsWith("Tool request denied")) {
    return "Tool denied; resuming analysis";
  }
  if (message === "Analysis started.") {
    return "Starting analysis";
  }

  return status === "running" ? "LLM thinking" : humanizeStatus(status);
}

function toolDisplayName(toolCall) {
  return toolCall?.exposed_tool_name || toolCall?.tool_name || "MCP tool";
}

function humanizeStatus(status) {
  return String(status || "idle").replaceAll("_", " ");
}

function selected() {
  return state.events.find((event) => event.event_id === state.selectedEventId) || null;
}

function isEventRunning(eventId) {
  return state.runningEventIds.has(eventId);
}

function isPhaseTwoRunning() {
  return Boolean(state.phase2Run && ACTIVE_ANALYSIS_STATUSES.has(state.phase2Run.status));
}

function canStopActiveTool() {
  const activeTool = state.phase2Run?.active_tool_execution;
  return Boolean(isPhaseTwoRunning() && activeTool?.status === "running");
}

function firstAvailableProvider() {
  return state.providers.find((provider) => provider.available) || null;
}

function modelsForProvider(providerId) {
  const provider = state.providers.find((item) => item.id === providerId);
  return provider && Array.isArray(provider.models) ? provider.models : [];
}

function providerLabel(providerId) {
  return state.providers.find((provider) => provider.id === providerId)?.label || providerId || "provider";
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.classList.toggle("error", isError);
}

function setAnalysisStatus(message, isError = false) {
  analysisStatus.textContent = message;
  analysisStatus.classList.toggle("error", isError);
}

function formatTime(timestamp) {
  if (!timestamp) {
    return "--:--:--";
  }
  return new Date(timestamp * 1000).toLocaleTimeString();
}

function markdownFromSummary(summary) {
  const packetId = summary.most_interesting_packet_id ?? "(not selected)";
  const recordingId = summary.recording_id ?? "(unknown)";
  const supporting = Array.isArray(summary.supporting_packet_ids) && summary.supporting_packet_ids.length
    ? summary.supporting_packet_ids.join(", ")
    : "(none)";
  return [
    `# Vulnerability Scan Phase 1 Summary - Event ${summary.event_id}`,
    "",
    `- Recording ID: ${recordingId}`,
    `- Most interesting packet ID: ${packetId}`,
    `- Supporting packet IDs: ${supporting}`,
    "",
    "## Packet Content",
    summary.packet_content || "(not provided)",
    "",
    "## Event Summary",
    summary.event_summary || "(not provided)",
    "",
    "## Suspected Trigger",
    summary.suspected_trigger || "(not provided)",
    "",
    "## Entrypoint Rationale",
    summary.entrypoint_rationale || "(not provided)",
  ].join("\n");
}

async function errorText(response) {
  try {
    const data = await response.json();
    return data.detail || JSON.stringify(data);
  } catch {
    return `HTTP ${response.status}`;
  }
}
