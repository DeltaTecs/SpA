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
    label: "Post Recon - Explorative",
    description: "Do not perform network scans or http analysis. Do not focus on authentication mechanisms. Perform a broad, explorative analysis of the remote service. Look for intricate, high impact vulnerabilities.",
  },
  {
    label: "Authentication",
    description: "Evaluate authentication, session, authorization, and access-control behavior in the event.",
  },
  {
    label: "Configuration",
    description: "Evaluate endpoint/cloud configuration of all remote endpoints in the event. Look for HTTP configuration, exposed storage/database, exposed secrets, etc.",
  },
  {
    label: "Custom",
    description: "Define your own analysis goal and choose which HexStrike tool set to enable.",
  },
];
const DEFAULT_ANALYSIS_TYPE = ANALYSIS_TYPES[0].label;
const CUSTOM_ANALYSIS_TYPE = "Custom";
// HexStrike tool sets the Custom analysis type can enable. Must match the keys
// of CUSTOM_HEXSTRIKE_TOOL_SETS in the backend analysis_types module.
const CUSTOM_TOOL_SETS = [
  "Network",
  "Domain",
  "HTTP/API",
  "Authentication",
  "Configuration",
  "Post-Recon General",
];
const DEFAULT_CUSTOM_TOOL_SET = CUSTOM_TOOL_SETS[0];
const ACTIVE_ANALYSIS_STATUSES = new Set(["queued", "running", "waiting_for_tool_approval"]);
const ACTIVE_PRESCAN_STATUSES = new Set(["queued", "running"]);
const PREFERRED_PROVIDER_MODELS = {
  deepseek: "deepseek-v4-pro",
};
const APPROVAL_MODES = [
  {value: "manual", label: "Manual approval", summary: "Manual approval"},
  {value: "auto_db", label: "Auto approve database tools", summary: "Auto-approve database tools"},
  {value: "auto_all", label: "Auto approve all tools", summary: "Auto-approve all tools"},
  {value: "smart_non_db", label: "Smart approve non-db tools", summary: "Smart approve (non-db)"},
];
const DEFAULT_APPROVAL_MODE = "manual";
const AUTO_DB_APPROVAL_MODE = "auto_db";
const AUTO_ALL_APPROVAL_MODE = "auto_all";
const SMART_APPROVAL_MODE = "smart_non_db";

const state = {
  events: [],
  selectedEventId: null,
  selectedReportKey: null,
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
  analysisType: DEFAULT_ANALYSIS_TYPE,
  analysisConstraints: "",
  customGoal: "",
  customToolSet: DEFAULT_CUSTOM_TOOL_SET,
  enablePhaseOneWebSearch: false,
  approvalMode: DEFAULT_APPROVAL_MODE,
  approvalProvider: null,
  approvalModel: null,
  escalateSmartRejections: true,
  phase2RunId: null,
  phase2Run: null,
  phase2PollTimer: null,
  phase1RunsByEvent: {},
  phase1PollTimer: null,
  storedReportsByEvent: {},
  loadingReportEventIds: new Set(),
  reportErrorsByEvent: {},
  priorReportIdsByEvent: {},
  compactIncludedReports: true,
  maxReasoningEffort: false,
  unlimitedRounds: false,
};

const eventList = document.querySelector("#eventList");
const eventCount = document.querySelector("#eventCount");
const storedReportPosition = document.querySelector("#storedReportPosition");
const refreshStoredReportsButton = document.querySelector("#refreshStoredReportsButton");
const storedReportList = document.querySelector("#storedReportList");
const detailPaneTitle = document.querySelector("#detailPaneTitle");
const eventDetail = document.querySelector("#eventDetail");
const reportDetail = document.querySelector("#reportDetail");
const selectedEvent = document.querySelector("#selectedEvent");
const selectedReportLabel = document.querySelector("#selectedReport");
const selectedReportMeta = document.querySelector("#selectedReportMeta");
const selectedReportBody = document.querySelector("#selectedReportBody");
const condensedSummarySection = document.querySelector("#condensedSummarySection");
const condensedSummaryBody = document.querySelector("#condensedSummaryBody");
const deleteCondensedSummaryButton = document.querySelector("#deleteCondensedSummaryButton");
const statusLine = document.querySelector("#statusLine");
const report = document.querySelector("#report");
const startButton = document.querySelector("#startButton");
const enablePhaseOneWebSearch = document.querySelector("#enablePhaseOneWebSearch");
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
const analysisTypeSelect = document.querySelector("#analysisTypeSelect");
const customAnalysisField = document.querySelector("#customAnalysisField");
const customGoalInput = document.querySelector("#customGoalInput");
const customToolSetSelect = document.querySelector("#customToolSetSelect");
const startAnalysisButton = document.querySelector("#startAnalysisButton");
const abortAnalysisButton = document.querySelector("#abortAnalysisButton");
const stopToolButton = document.querySelector("#stopToolButton");
const configureApprovalButton = document.querySelector("#configureApprovalButton");
const approvalModeSummary = document.querySelector("#approvalModeSummary");
const approvalConfigDialog = document.querySelector("#approvalConfigDialog");
const approvalDialogCloseButton = document.querySelector("#approvalDialogCloseButton");
const approvalLlmConfig = document.querySelector("#approvalLlmConfig");
const approvalProviderSelect = document.querySelector("#approvalProviderSelect");
const approvalModelSelect = document.querySelector("#approvalModelSelect");
const escalateSmartRejections = document.querySelector("#escalateSmartRejections");
const approvalModeRadios = document.querySelectorAll('input[name="approvalMode"]');
const constraintsInput = document.querySelector("#constraintsInput");
const analysisStatus = document.querySelector("#analysisStatus");
const analysisProcess = document.querySelector("#analysisProcess");
const analysisProcessText = document.querySelector("#analysisProcessText");
const prescanProcess = document.querySelector("#prescanProcess");
const prescanProcessText = document.querySelector("#prescanProcessText");
const toolApprovals = document.querySelector("#toolApprovals");
const analysisProgress = document.querySelector("#analysisProgress");
const priorReportsList = document.querySelector("#priorReportsList");
const priorReportsSummary = document.querySelector("#priorReportsSummary");
const compactIncludedReports = document.querySelector("#compactIncludedReports");
const maxReasoningEffort = document.querySelector("#maxReasoningEffort");
const unlimitedRounds = document.querySelector("#unlimitedRounds");

refreshButton.addEventListener("click", loadEvents);
deleteCondensedSummaryButton.addEventListener("click", deleteCondensedSummary);
refreshStoredReportsButton.addEventListener("click", () => refreshStoredReportsForSelectedEvent());
startButton.addEventListener("click", startPhaseOne);
enablePhaseOneWebSearch.addEventListener("change", () => {
  state.enablePhaseOneWebSearch = enablePhaseOneWebSearch.checked;
  renderDetailPane();
});
phaseOneTab.addEventListener("click", () => setActiveTab("phase1"));
vulnerabilityTab.addEventListener("click", () => setActiveTab("phase2"));
analysisTypeSelect.addEventListener("change", () => {
  state.analysisType = analysisTypeSelect.value;
  renderPhaseTwo();
});
customGoalInput.addEventListener("input", () => {
  state.customGoal = customGoalInput.value;
  renderPhaseTwo();
});
customToolSetSelect.addEventListener("change", () => {
  state.customToolSet = customToolSetSelect.value;
});
startAnalysisButton.addEventListener("click", startPhaseTwo);
abortAnalysisButton.addEventListener("click", abortPhaseTwo);
stopToolButton.addEventListener("click", stopActiveTool);
configureApprovalButton.addEventListener("click", openApprovalDialog);
approvalDialogCloseButton.addEventListener("click", () => approvalConfigDialog.close());
approvalConfigDialog.addEventListener("close", renderPhaseTwo);
approvalConfigDialog.addEventListener("click", (event) => {
  if (event.target === approvalConfigDialog) {
    approvalConfigDialog.close();
  }
});
for (const radio of approvalModeRadios) {
  radio.addEventListener("change", () => {
    if (radio.checked) {
      state.approvalMode = radio.value;
      renderApprovalDialog();
    }
  });
}
approvalProviderSelect.addEventListener("change", () => {
  state.approvalProvider = approvalProviderSelect.value;
  state.approvalModel = defaultModelForProvider(state.approvalProvider);
  renderApprovalDialog();
});
approvalModelSelect.addEventListener("change", () => {
  state.approvalModel = approvalModelSelect.value;
});
escalateSmartRejections.addEventListener("change", () => {
  state.escalateSmartRejections = escalateSmartRejections.checked;
});
compactIncludedReports.addEventListener("change", () => {
  state.compactIncludedReports = compactIncludedReports.checked;
  renderPhaseTwo();
});
maxReasoningEffort.addEventListener("change", () => {
  state.maxReasoningEffort = maxReasoningEffort.checked;
  renderPhaseTwo();
});
unlimitedRounds.addEventListener("change", () => {
  state.unlimitedRounds = unlimitedRounds.checked;
  renderPhaseTwo();
});
constraintsInput.addEventListener("input", () => {
  state.analysisConstraints = constraintsInput.value;
  renderPhaseTwo();
});
providerSelect.addEventListener("change", () => {
  state.selectedProvider = providerSelect.value;
  state.selectedModel = defaultModelForProvider(state.selectedProvider);
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
    state.selectedModel = defaultModelForProvider(state.selectedProvider, config.model);
    state.approvalProvider = state.selectedProvider;
    state.approvalModel = defaultModelForProvider(state.approvalProvider);
    state.appDetailsFileName = "";
    state.appDetailsContent = null;
    state.userIntendFileName = "";
    state.userIntendContent = null;
    renderConfig();
  } catch (error) {
    state.providers = [];
    state.selectedProvider = null;
    state.selectedModel = null;
    state.approvalProvider = null;
    state.approvalModel = null;
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
      state.selectedReportKey = null;
    }
    renderEvents();
    loadStoredReportsForSelectedEvent({force: true});
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
  } catch (error) {
    setStatus(`Could not load stored evaluations: ${error.message}`, true);
  }
}

async function loadStoredReportsForSelectedEvent(options = {}) {
  const event = selected();
  if (!event) {
    renderStoredReports();
    return;
  }
  await loadStoredReports(event.event_id, options);
}

async function refreshStoredReportsForSelectedEvent() {
  await loadStoredReportsForSelectedEvent({force: true});
}

async function loadStoredReports(eventId, options = {}) {
  if (!options.force && state.storedReportsByEvent[eventId]) {
    syncSelectedReportForEvent(eventId);
    renderEvents();
    return;
  }
  if (state.loadingReportEventIds.has(eventId)) {
    return;
  }

  state.loadingReportEventIds.add(eventId);
  state.reportErrorsByEvent[eventId] = "";
  renderStoredReports();
  try {
    const response = await fetch(`/api/events/${eventId}/scans`);
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    const reports = await response.json();
    state.storedReportsByEvent[eventId] = Array.isArray(reports) ? reports : [];
    syncSelectedReportForEvent(eventId);
  } catch (error) {
    state.reportErrorsByEvent[eventId] = error.message;
  } finally {
    state.loadingReportEventIds.delete(eventId);
    renderEvents();
  }
}

async function startPhaseOne() {
  const event = selected();
  // Only this event's own in-progress scan blocks a restart; a pre-scan running
  // on a different event must not stand in the way.
  if (!event || isEventRunning(event.event_id)) {
    return;
  }

  state.runningEventIds.add(event.event_id);
  renderConfig();
  renderEvents();
  renderDetailPane();
  setStatus(`Starting pre-scan for event ${event.event_id} with ${providerLabel(state.selectedProvider)} ${state.selectedModel}...`);

  try {
    const payload = {
      event_id: event.event_id,
      enable_web_search: state.enablePhaseOneWebSearch,
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
    const run = await response.json();
    state.phase1RunsByEvent[run.event_id] = run;
    renderDetailPane();
    schedulePhaseOnePolling();
  } catch (error) {
    state.runningEventIds.delete(event.event_id);
    setStatus(`Pre-scan failed for event ${event.event_id}: ${error.message}`, true);
    renderConfig();
    renderEvents();
    renderDetailPane();
  }
}

// A single shared timer drives every active pre-scan; it keeps polling until no
// event has a run in progress, so concurrent scans are all covered.
function schedulePhaseOnePolling() {
  if (!state.phase1PollTimer) {
    state.phase1PollTimer = window.setInterval(refreshPhaseOneRuns, 1500);
  }
  refreshPhaseOneRuns();
}

function stopPhaseOnePolling() {
  if (state.phase1PollTimer) {
    window.clearInterval(state.phase1PollTimer);
    state.phase1PollTimer = null;
  }
}

async function refreshPhaseOneRuns() {
  const activeRuns = Object.values(state.phase1RunsByEvent).filter(
    (run) => ACTIVE_PRESCAN_STATUSES.has(run.status),
  );
  if (activeRuns.length === 0) {
    stopPhaseOnePolling();
    return;
  }

  await Promise.all(activeRuns.map(refreshPhaseOneRun));

  if (!hasActivePhaseOneRuns()) {
    stopPhaseOnePolling();
  }
  renderConfig();
  renderEvents();
  renderDetailPane();
}

// Fetches one run's latest snapshot and folds it back into state. Never throws:
// a failed poll is recorded against its own event so it cannot stall the others.
async function refreshPhaseOneRun(previous) {
  try {
    const response = await fetch(`/api/phase1/${previous.run_id}`);
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    const run = await response.json();
    state.phase1RunsByEvent[run.event_id] = run;
    if (run.status === "completed") {
      state.results[run.event_id] = {
        event_id: run.event_id,
        recording_id: run.recording_id,
        markdown: run.result_markdown,
        summary: run.summary,
      };
      state.runningEventIds.delete(run.event_id);
      setStatus(`Pre-scan complete for event ${run.event_id}.`);
    } else if (run.status === "failed") {
      state.runningEventIds.delete(run.event_id);
      setStatus(`Pre-scan failed for event ${run.event_id}: ${run.error || "unknown error"}`, true);
    }
  } catch (error) {
    state.runningEventIds.delete(previous.event_id);
    state.phase1RunsByEvent[previous.event_id] = {
      ...previous,
      status: "failed",
      error: error.message,
    };
    setStatus(`Could not refresh pre-scan for event ${previous.event_id}: ${error.message}`, true);
  }
}

async function startPhaseTwo() {
  const event = selected();
  if (!event || isPhaseTwoRunning() || !state.analysisType || customAnalysisIncomplete()) {
    return;
  }

  const payload = {
    event_id: event.event_id,
    analysis_types: [state.analysisType],
    constraints: state.analysisConstraints,
    approval_mode: state.approvalMode,
    provider: state.selectedProvider,
    model: state.selectedModel,
    prior_report_ids: selectedPriorReportIdsForEvent(event.event_id),
    compact_included_reports: state.compactIncludedReports,
    max_reasoning_effort: state.maxReasoningEffort,
    unlimited_rounds: state.unlimitedRounds,
    ...(isCustomAnalysisSelected()
      ? {custom_goal: state.customGoal.trim(), custom_tool_set: state.customToolSet}
      : {}),
    ...approvalPayload(),
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

async function decideToolRequest(requestId, approved, reason = "") {
  if (!state.phase2RunId) {
    return;
  }
  try {
    const response = await fetch(`/api/phase2/${state.phase2RunId}/tool-requests/${requestId}/decision`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({approved, reason}),
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
    if (state.phase2Run.status === "completed") {
      await loadStoredReports(state.phase2Run.event_id, {force: true});
    }
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
    state.selectedModel = defaultModelForProvider(state.selectedProvider);
  }

  const models = modelsForProvider(state.selectedProvider);
  if (!models.includes(state.selectedModel)) {
    state.selectedModel = defaultModelForProvider(state.selectedProvider);
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
    renderDetailPane();
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
  renderDetailPane();
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
      state.selectedReportKey = null;
      renderEvents();
      loadStoredReportsForSelectedEvent();
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
    const recording = event.recording_ids.length ? event.recording_ids[0] : "unknown";
    const evaluationState = isEventRunning(event.event_id)
      ? "evaluating"
      : state.results[event.event_id]
        ? "evaluated"
        : "not evaluated";
    const reportCount = state.storedReportsByEvent[event.event_id]?.length;
    const reportText = reportCount === undefined
      ? ""
      : `, ${reportCount} ${reportCount === 1 ? "report" : "reports"}`;
    meta.textContent = `${event.packet_count} packets, recording ${recording}, ${evaluationState}${reportText}`;

    button.append(title, meta);
    eventList.append(button);
  }

  renderDetailPane();
  renderStoredReports();
}

function renderDetailPane() {
  const reportItem = selectedReport();
  const showingReport = Boolean(reportItem);
  detailPaneTitle.textContent = showingReport ? "Report" : "Event";
  eventDetail.classList.toggle("active", !showingReport);
  reportDetail.classList.toggle("active", showingReport);
  renderEventDetail();
  renderSelectedReport(reportItem);
}

function renderEventDetail() {
  const event = selected();
  const isRunning = event ? isEventRunning(event.event_id) : false;
  startButton.textContent = isRunning ? "Evaluating..." : "Evaluate";
  startButton.disabled = isRunning || !event || !state.selectedProvider || !state.selectedModel;
  enablePhaseOneWebSearch.checked = state.enablePhaseOneWebSearch;
  enablePhaseOneWebSearch.disabled = isRunning;
  selectedEvent.textContent = event
    ? `Selected event ${event.event_id}: ${event.description || "(no description)"}`
    : "Select an event.";

  renderPrescanProcess();

  if (!event) {
    report.innerHTML = "";
    renderPhaseTwo();
    return;
  }
  if (isRunning) {
    report.innerHTML = renderMarkdown(`Pre-scan is running for event ${event.event_id}.`);
    renderPhaseTwo();
    return;
  }
  const result = state.results[event.event_id];
  report.innerHTML = renderMarkdown(result?.markdown || "No stored evaluation for this event.");
  renderPhaseTwo();
}

function renderPrescanProcess() {
  const process = currentPrescanProcess();
  prescanProcessText.textContent = process.label;
  prescanProcess.classList.toggle("active", process.active);
  prescanProcess.classList.toggle("terminal", process.terminal);
  prescanProcess.classList.toggle("error", process.error);
}

// Describes the pre-scan status for the currently selected event only, so the
// status box follows event selection instead of a single global scan.
function currentPrescanProcess() {
  const event = selected();
  if (!event) {
    return {label: "Idle", active: false, terminal: false, error: false};
  }

  const run = state.phase1RunsByEvent[event.event_id] || null;

  // A pre-scan was just started for this event but no run snapshot exists yet:
  // either the POST is still in flight, or only a stale terminal run is on file.
  if (
    isEventRunning(event.event_id)
    && (!run || run.status === "completed" || run.status === "failed")
  ) {
    return {label: "Starting pre-scan...", active: true, terminal: false, error: false};
  }

  if (!run) {
    return {label: "Idle", active: false, terminal: false, error: false};
  }

  const latestMessage = latestProgressMessage(run);
  if (run.status === "completed") {
    return {label: latestMessage || "Pre-scan completed.", active: false, terminal: true, error: false};
  }
  if (run.status === "failed") {
    return {label: latestMessage || `Pre-scan failed: ${run.error || "unknown error"}`, active: false, terminal: true, error: true};
  }
  if (run.status === "queued") {
    return {label: latestMessage || "Queued", active: true, terminal: false, error: false};
  }

  return {
    label: latestMessage || humanizeStatus(run.status),
    active: true,
    terminal: false,
    error: false,
  };
}

function renderSelectedReport(reportItem) {
  if (!reportItem) {
    selectedReportLabel.textContent = "Select a report from the reports list.";
    selectedReportMeta.textContent = "";
    selectedReportBody.innerHTML = "";
    renderCondensedSummary(null);
    return;
  }

  selectedReportLabel.textContent = `Selected report ${reportItem.scan_id} for event ${reportItem.event_id}.`;
  selectedReportMeta.textContent = storedReportMetaText(reportItem);
  selectedReportBody.innerHTML = renderMarkdown(reportItem.summary || "(empty report)");
  renderCondensedSummary(reportItem);
}

function renderCondensedSummary(reportItem) {
  const condensed = reportItem?.condensed_summary?.trim();
  if (!condensed) {
    condensedSummarySection.hidden = true;
    condensedSummaryBody.innerHTML = "";
    deleteCondensedSummaryButton.disabled = true;
    return;
  }
  condensedSummarySection.hidden = false;
  condensedSummaryBody.innerHTML = renderMarkdown(condensed);
  deleteCondensedSummaryButton.disabled = false;
}

async function deleteCondensedSummary() {
  const reportItem = selectedReport();
  if (!reportItem || !reportItem.condensed_summary) {
    return;
  }
  const scanId = reportItem.scan_id;
  deleteCondensedSummaryButton.disabled = true;
  try {
    const response = await fetch(`/api/scans/${scanId}/condensed-summary`, {method: "DELETE"});
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    reportItem.condensed_summary = "";
    setStatus(`Deleted condensed summary for report ${scanId}.`);
  } catch (error) {
    setStatus(`Could not delete condensed summary for report ${scanId}: ${error.message}`, true);
  } finally {
    renderDetailPane();
  }
}

function renderStoredReports() {
  const event = selected();
  storedReportList.innerHTML = "";
  if (!event) {
    storedReportPosition.textContent = "0 reports";
    refreshStoredReportsButton.disabled = true;
    appendReportListMessage("Select an event.");
    return;
  }

  const eventId = event.event_id;
  const isLoading = state.loadingReportEventIds.has(eventId);
  const error = state.reportErrorsByEvent[eventId];
  const reports = state.storedReportsByEvent[eventId] || [];
  const reportCount = reports.length;

  storedReportPosition.textContent = `${reportCount} ${reportCount === 1 ? "report" : "reports"}`;
  refreshStoredReportsButton.disabled = isLoading;

  if (isLoading) {
    appendReportListMessage(`Loading reports for event ${eventId}...`);
    return;
  }
  if (error) {
    appendReportListMessage(`Could not load reports for event ${eventId}: ${error}`, true);
    return;
  }
  if (reportCount === 0) {
    appendReportListMessage(`No stored reports for event ${eventId}.`);
    return;
  }

  for (const reportItem of reports) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `report-row${reportKey(reportItem) === state.selectedReportKey ? " selected" : ""}`;
    button.addEventListener("click", () => {
      state.selectedEventId = eventId;
      state.selectedReportKey = reportKey(reportItem);
      renderEvents();
    });

    const title = document.createElement("div");
    title.className = "report-row-title";

    const type = document.createElement("div");
    type.className = "report-type";
    type.textContent = reportItem.scan_type_title || "Unknown scan type";

    const id = document.createElement("div");
    id.className = "event-id";
    id.textContent = `#${reportItem.scan_id}`;

    const meta = document.createElement("div");
    meta.className = "event-meta";
    meta.textContent = reportRowMetaText(reportItem);

    title.append(type, id);
    button.append(title, meta);
    storedReportList.append(button);
  }
}

function appendReportListMessage(message, isError = false) {
  const empty = document.createElement("div");
  empty.className = `report-list-message${isError ? " error" : ""}`;
  empty.textContent = message;
  storedReportList.append(empty);
}

function reportRowMetaText(reportItem) {
  const provider = reportItem.llm_provider || "provider";
  const model = reportItem.llm_model || "model";
  const tools = reportItem.tools_used?.trim();
  return tools ? `${provider} / ${model}, tools: ${tools}` : `${provider} / ${model}`;
}

// Collapses the stored comma-separated tool list into unique names, keeping the
// order in which each tool first appears so a tool used repeatedly is shown once.
function uniqueToolNames(toolsUsed) {
  const names = (toolsUsed || "")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  return [...new Set(names)];
}

// Formats a scan's wall-clock duration (seconds) as a compact human string,
// e.g. 45 -> "45s", 154 -> "2m 34s", 3725 -> "1h 2m". Returns a placeholder
// for reports recorded before duration tracking existed.
function formatScanDuration(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) {
    return "(not recorded)";
  }
  const total = Math.round(seconds);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}

function storedReportMetaText(reportItem) {
  const tools = uniqueToolNames(reportItem.tools_used);
  const toolsUsed = tools.length ? tools.join(", ") : "(none recorded)";
  const constraints = reportItem.user_constrains?.trim() || "(none)";
  return [
    `Report #${reportItem.scan_id} - ${reportItem.scan_type_title || "Unknown scan type"}`,
    `${reportItem.llm_provider || "provider"} / ${reportItem.llm_model || "model"}`,
    `Tools: ${toolsUsed}`,
    `Constraints: ${constraints}`,
    `Duration: ${formatScanDuration(reportItem.duration)}`,
  ].join("\n");
}

function renderPhaseTwo() {
  constraintsInput.value = state.analysisConstraints;
  const running = isPhaseTwoRunning();
  maxReasoningEffort.checked = state.maxReasoningEffort;
  maxReasoningEffort.disabled = running;
  unlimitedRounds.checked = state.unlimitedRounds;
  unlimitedRounds.disabled = running;
  renderAnalysisTypeSelect(running);
  renderCustomAnalysisFields(running);
  configureApprovalButton.disabled = running;
  approvalModeSummary.textContent = approvalSummary();

  const event = selected();
  const hasPrescan = Boolean(event && state.results[event.event_id]);
  startAnalysisButton.disabled = running || !event || !hasPrescan || !state.selectedProvider || !state.selectedModel || !state.analysisType || customAnalysisIncomplete();
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
  } else if (!hasPrescan) {
    setAnalysisStatus(
      `Run the pre-scan for event ${event.event_id} before starting vulnerability analysis.`,
      true,
    );
  } else if (!state.analysisType) {
    setAnalysisStatus("Select a vulnerability analysis type.");
  } else if (customAnalysisIncomplete()) {
    setAnalysisStatus("Enter a custom analysis goal before starting.");
  } else {
    setAnalysisStatus("Ready to start vulnerability analysis.");
  }

  renderToolApprovals();
  renderAnalysisProcess();
  renderAnalysisProgress();
  renderPriorReports(running);
}

function renderPriorReports(running) {
  priorReportsList.innerHTML = "";
  compactIncludedReports.checked = state.compactIncludedReports;

  const event = selected();
  if (!event) {
    compactIncludedReports.disabled = true;
    priorReportsSummary.textContent = "Select an event to see its prior reports.";
    appendPriorReportListMessage("Select an event.");
    return;
  }

  pruneSelectedPriorReportIds(event.event_id);

  const eventId = event.event_id;
  const reports = state.storedReportsByEvent[eventId];
  const loading = state.loadingReportEventIds.has(eventId);
  const error = state.reportErrorsByEvent[eventId];
  const selectedIds = state.priorReportIdsByEvent[eventId] || new Set();
  compactIncludedReports.disabled = running;

  priorReportsSummary.textContent = selectedIds.size
    ? `${selectedIds.size} selected`
    : "None selected";

  if (loading && !reports) {
    appendPriorReportListMessage(`Loading reports for event ${eventId}...`);
    return;
  }
  if (error && !reports) {
    appendPriorReportListMessage(`Could not load reports: ${error}`, true);
    return;
  }
  if (!reports || reports.length === 0) {
    appendPriorReportListMessage("No stored reports available for this event yet.");
    return;
  }

  for (const reportItem of reports) {
    const row = document.createElement("label");
    row.className = "prior-report-row";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = selectedIds.has(reportItem.scan_id);
    checkbox.disabled = running;
    checkbox.addEventListener("change", () => {
      togglePriorReportSelection(eventId, reportItem.scan_id, checkbox.checked);
    });

    const text = document.createElement("div");
    text.className = "prior-report-row-text";

    const title = document.createElement("div");
    title.className = "prior-report-row-title";
    const type = document.createElement("span");
    type.className = "report-type";
    type.textContent = reportItem.scan_type_title || "Unknown scan type";
    const id = document.createElement("span");
    id.className = "event-id";
    id.textContent = `#${reportItem.scan_id}`;
    title.append(type, id);

    const meta = document.createElement("div");
    meta.className = "event-meta";
    meta.textContent = reportRowMetaText(reportItem);

    text.append(title, meta);
    row.append(checkbox, text);
    priorReportsList.append(row);
  }
}

function appendPriorReportListMessage(message, isError = false) {
  const empty = document.createElement("div");
  empty.className = `report-list-message${isError ? " error" : ""}`;
  empty.textContent = message;
  priorReportsList.append(empty);
}

function togglePriorReportSelection(eventId, scanId, checked) {
  const selectedIds = state.priorReportIdsByEvent[eventId] || new Set();
  if (checked) {
    selectedIds.add(scanId);
  } else {
    selectedIds.delete(scanId);
  }
  state.priorReportIdsByEvent[eventId] = selectedIds;
  renderPhaseTwo();
}

function pruneSelectedPriorReportIds(eventId) {
  const selectedIds = state.priorReportIdsByEvent[eventId];
  const reports = state.storedReportsByEvent[eventId];
  if (!selectedIds || selectedIds.size === 0 || !reports) {
    return;
  }
  const availableIds = new Set(reports.map((item) => item.scan_id));
  for (const scanId of [...selectedIds]) {
    if (!availableIds.has(scanId)) {
      selectedIds.delete(scanId);
    }
  }
}

function selectedPriorReportIdsForEvent(eventId) {
  const selectedIds = state.priorReportIdsByEvent[eventId];
  return selectedIds ? [...selectedIds] : [];
}

function renderAnalysisTypeSelect(running) {
  if (!ANALYSIS_TYPES.some((type) => type.label === state.analysisType)) {
    state.analysisType = DEFAULT_ANALYSIS_TYPE;
  }

  if (analysisTypeSelect.options.length !== ANALYSIS_TYPES.length) {
    analysisTypeSelect.innerHTML = "";
    for (const type of ANALYSIS_TYPES) {
      const option = document.createElement("option");
      option.value = type.label;
      option.textContent = type.label;
      option.title = type.description;
      analysisTypeSelect.append(option);
    }
  }

  analysisTypeSelect.value = state.analysisType;
  analysisTypeSelect.disabled = running;
}

function isCustomAnalysisSelected() {
  return state.analysisType === CUSTOM_ANALYSIS_TYPE;
}

// The Custom type cannot start without a goal; the tool set always has a value.
function customAnalysisIncomplete() {
  return isCustomAnalysisSelected() && !state.customGoal.trim();
}

function renderCustomAnalysisFields(running) {
  customAnalysisField.hidden = !isCustomAnalysisSelected();

  if (customToolSetSelect.options.length !== CUSTOM_TOOL_SETS.length) {
    customToolSetSelect.innerHTML = "";
    for (const name of CUSTOM_TOOL_SETS) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      customToolSetSelect.append(option);
    }
  }
  if (!CUSTOM_TOOL_SETS.includes(state.customToolSet)) {
    state.customToolSet = DEFAULT_CUSTOM_TOOL_SET;
  }

  customGoalInput.value = state.customGoal;
  customToolSetSelect.value = state.customToolSet;
  customGoalInput.disabled = running;
  customToolSetSelect.disabled = running;
}

function approvalSummary() {
  const mode = APPROVAL_MODES.find((item) => item.value === state.approvalMode) || APPROVAL_MODES[0];
  if (state.approvalMode === SMART_APPROVAL_MODE && state.approvalProvider && state.approvalModel) {
    return `${mode.summary} · ${providerLabel(state.approvalProvider)} / ${state.approvalModel}`;
  }
  return mode.summary;
}

function openApprovalDialog() {
  renderApprovalDialog();
  if (typeof approvalConfigDialog.showModal === "function") {
    approvalConfigDialog.showModal();
  } else {
    approvalConfigDialog.setAttribute("open", "");
  }
}

// Populates the approval dialog: radio selection and the smart-approver LLM
// dropdowns. The provider/model controls are only enabled for the smart mode.
function renderApprovalDialog() {
  for (const radio of approvalModeRadios) {
    radio.checked = radio.value === state.approvalMode;
  }

  const smartMode = state.approvalMode === SMART_APPROVAL_MODE;
  approvalLlmConfig.classList.toggle("active", smartMode);

  const availableProviders = state.providers.filter((provider) => provider.available);
  if (!availableProviders.some((provider) => provider.id === state.approvalProvider)) {
    state.approvalProvider = availableProviders[0]?.id || null;
    state.approvalModel = defaultModelForProvider(state.approvalProvider);
  }

  const models = modelsForProvider(state.approvalProvider);
  if (!models.includes(state.approvalModel)) {
    state.approvalModel = defaultModelForProvider(state.approvalProvider);
  }

  approvalProviderSelect.innerHTML = "";
  for (const provider of availableProviders) {
    const option = document.createElement("option");
    option.value = provider.id;
    option.textContent = provider.has_api_key ? `${provider.label} (key configured)` : provider.label;
    approvalProviderSelect.append(option);
  }

  approvalModelSelect.innerHTML = "";
  for (const model of models) {
    const option = document.createElement("option");
    option.value = model;
    option.textContent = model;
    approvalModelSelect.append(option);
  }

  approvalProviderSelect.value = state.approvalProvider || "";
  approvalModelSelect.value = state.approvalModel || "";
  approvalProviderSelect.disabled = !smartMode || availableProviders.length === 0;
  approvalModelSelect.disabled = !smartMode || models.length === 0;

  escalateSmartRejections.checked = state.escalateSmartRejections;
  escalateSmartRejections.disabled = !smartMode;
}

// Extra phase-two payload fields that only apply to the smart approval mode.
function approvalPayload() {
  if (state.approvalMode !== SMART_APPROVAL_MODE) {
    return {};
  }
  return {
    approval_provider: state.approvalProvider,
    approval_model: state.approvalModel,
    escalate_smart_rejections: state.escalateSmartRejections,
  };
}

function renderToolApprovals() {
  toolApprovals.innerHTML = "";
  const run = state.phase2Run;
  const pending = state.phase2Run?.pending_tool_requests || [];
  for (const request of pending) {
    const card = document.createElement("div");
    card.className = "tool-approval";

    const title = document.createElement("div");
    title.className = "tool-approval-title";
    title.textContent = `Tool permission request ${request.request_id}`;

    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(request.tool_call, null, 2);

    card.append(title, pre);
    if (request.smart_review) {
      card.append(renderSmartReview(request.smart_review));
    }
    if (shouldRenderManualApprovalControls(run, request)) {
      const reasonInput = document.createElement("input");
      reasonInput.type = "text";
      reasonInput.className = "tool-approval-reason";
      reasonInput.placeholder = "Optional reason for denial (returned to the analysis LLM)";

      const actions = document.createElement("div");
      actions.className = "tool-approval-actions";

      const deny = document.createElement("button");
      deny.type = "button";
      deny.textContent = "Deny";
      deny.addEventListener("click", () => decideToolRequest(request.request_id, false, reasonInput.value));

      const approve = document.createElement("button");
      approve.type = "button";
      approve.textContent = "Approve";
      approve.addEventListener("click", () => decideToolRequest(request.request_id, true));

      actions.append(deny, approve);
      card.append(reasonInput, actions);
    } else {
      card.append(renderAutomatedApprovalNotice(request));
    }
    toolApprovals.append(card);
  }
}

function shouldRenderManualApprovalControls(run, request) {
  const approvalMode = run?.approval_mode || state.approvalMode;
  if (approvalMode === AUTO_ALL_APPROVAL_MODE) {
    return false;
  }
  if (
    approvalMode === AUTO_DB_APPROVAL_MODE
    && isMcpDatabaseToolCall(request.tool_call)
  ) {
    return false;
  }
  if (approvalMode !== SMART_APPROVAL_MODE) {
    return true;
  }
  if (isMcpDatabaseToolCall(request.tool_call)) {
    return false;
  }
  const review = request.smart_review;
  const wasRejectedBySmartApprover = review && (!review.approved || review.error);
  return Boolean(wasRejectedBySmartApprover && run?.escalate_smart_rejections);
}

function isMcpDatabaseToolCall(toolCall = {}) {
  const serverId = String(toolCall.server_id || "").trim().toLowerCase();
  const serverLabel = String(toolCall.server_label || "").trim().toLowerCase();
  return ["packet", "packet_db", "mcp_packet_db"].includes(serverId) || serverLabel === "packet db";
}

function renderAutomatedApprovalNotice(request) {
  const box = document.createElement("div");
  box.className = "tool-approval-auto";
  box.textContent = request.smart_review
    ? "Automated approval has resolved this request."
    : "Automated approval is reviewing this request.";
  return box;
}

// Shows why the smart approver escalated a tool call to manual approval.
function renderSmartReview(review) {
  const approved = Boolean(review.approved) && !review.error;
  const box = document.createElement("div");
  box.className = `tool-approval-review${approved ? "" : " flagged"}`;

  const heading = document.createElement("div");
  heading.className = "tool-approval-review-heading";
  heading.textContent = review.error
    ? "Smart approver could not evaluate this call"
    : approved
      ? "Smart approver approved this call"
      : "Smart approver flagged this call for manual review";

  const reason = document.createElement("div");
  reason.className = "tool-approval-review-reason";
  reason.textContent = review.reasoning || "(no reasoning provided)";

  box.append(heading, reason);
  return box;
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

  const latestMessage = latestProgressMessage(run);
  if (run.status === "completed") {
    return {label: latestMessage || "Analysis completed.", active: false, terminal: true, error: false};
  }
  if (run.status === "failed") {
    return {label: latestMessage || `Analysis failed: ${run.error || "unknown error"}`, active: false, terminal: true, error: true};
  }
  if (run.status === "aborted") {
    return {label: latestMessage || "Analysis aborted.", active: false, terminal: true, error: false};
  }
  if (run.status === "queued") {
    return {label: latestMessage || "Queued", active: true, terminal: false, error: false};
  }

  return {
    label: latestMessage || humanizeStatus(run.status),
    active: isPhaseTwoRunning(),
    terminal: false,
    error: false,
  };
}

function latestProgressMessage(run) {
  const progress = Array.isArray(run.progress) ? run.progress : [];
  return progress[progress.length - 1]?.message || "";
}

function humanizeStatus(status) {
  return String(status || "idle").replaceAll("_", " ");
}

function selected() {
  return state.events.find((event) => event.event_id === state.selectedEventId) || null;
}

function selectedReport() {
  const event = selected();
  if (!event || !state.selectedReportKey) {
    return null;
  }
  return (state.storedReportsByEvent[event.event_id] || [])
    .find((reportItem) => reportKey(reportItem) === state.selectedReportKey) || null;
}

function syncSelectedReportForEvent(eventId) {
  if (eventId !== state.selectedEventId || !state.selectedReportKey) {
    return;
  }

  const reports = state.storedReportsByEvent[eventId] || [];
  if (!reports.some((reportItem) => reportKey(reportItem) === state.selectedReportKey)) {
    state.selectedReportKey = null;
  }
}

function reportKey(reportItem) {
  return String(reportItem.scan_id);
}

function isEventRunning(eventId) {
  return state.runningEventIds.has(eventId);
}

function isPhaseTwoRunning() {
  return Boolean(state.phase2Run && ACTIVE_ANALYSIS_STATUSES.has(state.phase2Run.status));
}

function hasActivePhaseOneRuns() {
  return Object.values(state.phase1RunsByEvent).some(
    (run) => ACTIVE_PRESCAN_STATUSES.has(run.status),
  );
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

function defaultModelForProvider(providerId, fallbackModel = null) {
  const models = modelsForProvider(providerId);
  const preferredModel = PREFERRED_PROVIDER_MODELS[providerId];
  if (preferredModel && models.includes(preferredModel)) {
    return preferredModel;
  }
  if (fallbackModel && models.includes(fallbackModel)) {
    return fallbackModel;
  }

  const providerDefault = state.providers.find((provider) => provider.id === providerId)?.default_model;
  if (providerDefault && models.includes(providerDefault)) {
    return providerDefault;
  }
  return models[0] || null;
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

// --- Minimal, dependency-free Markdown renderer -----------------------------
// Report bodies come from LLM output, so every piece of text is HTML-escaped
// before any markup is added. Raw HTML in the source is never passed through,
// which keeps the rendered report safe from script injection.

const MD_LIST_ITEM_RE = /^(\s*)([-*+]|\d{1,9}[.)])(\s+)(.*)$/;

function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, (char) => (
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[char]
  ));
}

// Renders a Markdown string to a safe HTML string.
function renderMarkdown(source) {
  if (source === null || source === undefined) {
    return "";
  }
  const lines = String(source).replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block (``` or ~~~).
    const fence = line.match(/^\s*(`{3,}|~{3,})(.*)$/);
    if (fence) {
      const marker = fence[1][0];
      const lang = fence[2].trim().split(/\s+/)[0];
      const body = [];
      i++;
      while (i < lines.length && !new RegExp(`^\\s*${marker}{3,}\\s*$`).test(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      i++; // skip the closing fence (if present)
      const langClass = lang ? ` class="language-${escapeHtml(lang)}"` : "";
      blocks.push(`<pre class="md-code"><code${langClass}>${escapeHtml(body.join("\n"))}</code></pre>`);
      continue;
    }

    // Blank line.
    if (/^\s*$/.test(line)) {
      i++;
      continue;
    }

    // ATX heading (# .. ######).
    const heading = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (heading) {
      const level = heading[1].length;
      blocks.push(`<h${level} class="md-h${level}">${renderInline(heading[2])}</h${level}>`);
      i++;
      continue;
    }

    // Thematic break.
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) {
      blocks.push('<hr class="md-hr">');
      i++;
      continue;
    }

    // GFM pipe table: a header row followed by a delimiter row.
    if (line.includes("|") && i + 1 < lines.length && isTableDelimiter(lines[i + 1])) {
      const header = line;
      const delimiter = lines[i + 1];
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && !/^\s*$/.test(lines[i])) {
        rows.push(lines[i]);
        i++;
      }
      blocks.push(renderTable(header, delimiter, rows));
      continue;
    }

    // Blockquote.
    if (/^\s*>/.test(line)) {
      const quoted = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        quoted.push(lines[i].replace(/^\s*>\s?/, ""));
        i++;
      }
      blocks.push(`<blockquote class="md-quote">${renderMarkdown(quoted.join("\n"))}</blockquote>`);
      continue;
    }

    // List (ordered or unordered, with indentation-based nesting).
    if (MD_LIST_ITEM_RE.test(line)) {
      const parsed = parseList(lines, i);
      blocks.push(parsed.html);
      i = parsed.next;
      continue;
    }

    // Paragraph: collect lines until a blank line or a new block starts.
    const paragraph = [];
    while (
      i < lines.length &&
      !/^\s*$/.test(lines[i]) &&
      !isBlockStart(lines[i], lines[i + 1])
    ) {
      paragraph.push(lines[i]);
      i++;
    }
    blocks.push(`<p class="md-p">${renderInline(paragraph.join("\n"))}</p>`);
  }

  return blocks.join("\n");
}

// Detects the start of a block-level construct, used to terminate paragraphs.
function isBlockStart(line, nextLine) {
  return (
    /^\s*(`{3,}|~{3,})/.test(line) ||
    /^#{1,6}\s+/.test(line) ||
    /^\s*([-*_])(\s*\1){2,}\s*$/.test(line) ||
    /^\s*>/.test(line) ||
    MD_LIST_ITEM_RE.test(line) ||
    (line.includes("|") && nextLine !== undefined && isTableDelimiter(nextLine))
  );
}

// Parses a list starting at `start`; returns the HTML and the next line index.
function parseList(lines, start) {
  const first = lines[start].match(MD_LIST_ITEM_RE);
  const indent = first[1].length;
  const ordered = /\d/.test(first[2]);
  const tag = ordered ? "ol" : "ul";
  const items = [];
  let i = start;

  const isSibling = (m) => Boolean(m) && m[1].length === indent && /\d/.test(m[2]) === ordered;

  while (i < lines.length) {
    const match = lines[i].match(MD_LIST_ITEM_RE);
    if (!isSibling(match)) {
      // A blank line is allowed between sibling items (loose list).
      if (/^\s*$/.test(lines[i])) {
        let j = i + 1;
        while (j < lines.length && /^\s*$/.test(lines[j])) {
          j++;
        }
        const next = j < lines.length ? lines[j].match(MD_LIST_ITEM_RE) : null;
        if (isSibling(next)) {
          i = j;
          continue;
        }
      }
      break;
    }

    // Lines indented past the marker belong to this item (continuation/nesting).
    const contentIndent = match[1].length + match[2].length + match[3].length;
    const body = [match[4]];
    i++;
    while (i < lines.length) {
      if (/^\s*$/.test(lines[i])) {
        let j = i + 1;
        while (j < lines.length && /^\s*$/.test(lines[j])) {
          j++;
        }
        const sibling = j < lines.length ? lines[j].match(MD_LIST_ITEM_RE) : null;
        const deeper = j < lines.length && lines[j].match(/^(\s*)/)[1].length >= contentIndent;
        if (deeper && !(sibling && sibling[1].length === indent)) {
          body.push("");
          i++;
          continue;
        }
        break;
      }
      const sibling = lines[i].match(MD_LIST_ITEM_RE);
      if (sibling && sibling[1].length === indent) {
        break;
      }
      if (lines[i].match(/^(\s*)/)[1].length < contentIndent) {
        break;
      }
      body.push(lines[i].slice(contentIndent));
      i++;
    }
    items.push(unwrapParagraph(renderMarkdown(body.join("\n"))));
  }

  const rendered = items.map((item) => `<li class="md-li">${item}</li>`).join("");
  return {html: `<${tag} class="md-list">${rendered}</${tag}>`, next: i};
}

// Strips the wrapping <p> from a single-paragraph list item so it renders tight.
function unwrapParagraph(html) {
  const match = html.match(/^<p class="md-p">([\s\S]*)<\/p>$/);
  if (match && !match[1].includes("<p ") && !match[1].includes("</p>")) {
    return match[1];
  }
  return html;
}

function isTableDelimiter(line) {
  return /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/.test(line);
}

// Splits a table row on unescaped pipes, trimming surrounding pipes and spaces.
function splitTableRow(line) {
  let text = line.trim();
  if (text.startsWith("|")) {
    text = text.slice(1);
  }
  if (text.endsWith("|") && !text.endsWith("\\|")) {
    text = text.slice(0, -1);
  }
  const cells = [];
  let current = "";
  for (let k = 0; k < text.length; k++) {
    if (text[k] === "\\" && text[k + 1] === "|") {
      current += "|";
      k++;
    } else if (text[k] === "|") {
      cells.push(current);
      current = "";
    } else {
      current += text[k];
    }
  }
  cells.push(current);
  return cells.map((cell) => cell.trim());
}

function renderTable(headerLine, delimiterLine, bodyLines) {
  const headers = splitTableRow(headerLine);
  const aligns = splitTableRow(delimiterLine).map((cell) => {
    const left = cell.startsWith(":");
    const right = cell.endsWith(":");
    if (left && right) {
      return "center";
    }
    return right ? "right" : left ? "left" : "";
  });
  const alignAttr = (index) => (aligns[index] ? ` style="text-align:${aligns[index]}"` : "");
  const headRow = headers
    .map((cell, index) => `<th${alignAttr(index)}>${renderInline(cell)}</th>`)
    .join("");
  const bodyRows = bodyLines
    .map((line) => {
      const cells = splitTableRow(line);
      const row = headers
        .map((_, index) => `<td${alignAttr(index)}>${renderInline(cells[index] || "")}</td>`)
        .join("");
      return `<tr>${row}</tr>`;
    })
    .join("");
  return `<table class="md-table"><thead><tr>${headRow}</tr></thead><tbody>${bodyRows}</tbody></table>`;
}

// Renders inline Markdown (code spans, links, emphasis) within a block of text.
function renderInline(text) {
  let escaped = escapeHtml(text);
  const codeSpans = [];
  const links = [];

  // Protect code spans first so their contents are never treated as markup.
  escaped = escaped.replace(/(`+)([^`]+?)\1/g, (match, ticks, code) => {
    codeSpans.push(`<code class="md-code-inline">${code.trim()}</code>`);
    return ` C${codeSpans.length - 1} `;
  });

  // Protect links so URLs are not mangled by the emphasis rules.
  escaped = escaped.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, (match, label, url) => {
    const href = sanitizeUrl(url);
    const inner = applyEmphasis(label);
    if (!href) {
      return inner;
    }
    links.push(`<a class="md-link" href="${href}" target="_blank" rel="noopener noreferrer">${inner}</a>`);
    return ` L${links.length - 1} `;
  });

  escaped = applyEmphasis(escaped).replace(/\n/g, "<br>");
  escaped = escaped.replace(/ L(\d+) /g, (match, index) => links[Number(index)]);
  escaped = escaped.replace(/ C(\d+) /g, (match, index) => codeSpans[Number(index)]);
  return escaped;
}

function applyEmphasis(text) {
  return text
    .replace(/\*\*\*([\s\S]+?)\*\*\*/g, "<strong><em>$1</em></strong>")
    .replace(/\*\*([\s\S]+?)\*\*/g, "<strong>$1</strong>")
    .replace(/__([\s\S]+?)__/g, "<strong>$1</strong>")
    .replace(/~~([\s\S]+?)~~/g, "<del>$1</del>")
    .replace(/(^|[^\w*])\*(?!\s)([^*]+?)\*(?!\w)/g, "$1<em>$2</em>")
    .replace(/(^|[^\w_])_(?!\s)([^_]+?)_(?!\w)/g, "$1<em>$2</em>");
}

// Allows only safe URL schemes; rejected URLs fall back to plain label text.
function sanitizeUrl(url) {
  const trimmed = url.trim();
  const decoded = trimmed.replace(/&amp;/g, "&");
  if (/^(https?:|mailto:)/i.test(decoded) || /^[/#.]/.test(decoded)) {
    return trimmed;
  }
  return null;
}
