/**
 * Rendering for the phase-two (vulnerability analysis) panel.
 *
 * Covers the analysis form (type selector, custom-analysis fields, constraints,
 * options), the prior-reports picker, the MCP approval-configuration dialog,
 * the pending tool-approval cards, and the run progress/status indicators.
 *
 * It also owns a handful of small phase-two domain helpers that the run
 * lifecycle (phase2.js) needs when building its request payload:
 * `isCustomAnalysisSelected`, `customAnalysisIncomplete`,
 * `selectedPriorReportIdsForEvent`, and `approvalPayload`.
 */

import {state} from "./state.js";
import {
  ANALYSIS_TYPES,
  APPROVAL_MODES,
  AUTO_ALL_APPROVAL_MODE,
  AUTO_DB_APPROVAL_MODE,
  CUSTOM_ANALYSIS_TYPE,
  CUSTOM_TOOL_SETS,
  DEFAULT_ANALYSIS_TYPE,
  DEFAULT_CUSTOM_TOOL_SET,
  SMART_APPROVAL_MODE,
} from "./constants.js";
import {
  abortAnalysisButton,
  analysisProcess,
  analysisProcessText,
  analysisProgress,
  analysisTypeSelect,
  approvalConfigDialog,
  approvalLlmConfig,
  approvalModelSelect,
  approvalModeRadios,
  approvalModeSummary,
  approvalProviderSelect,
  bashMode,
  compactIncludedReports,
  configureApprovalButton,
  constraintsInput,
  customAnalysisField,
  customGoalInput,
  customToolSetSelect,
  escalateSmartRejections,
  maxReasoningEffort,
  priorReportsList,
  priorReportsSummary,
  startAnalysisButton,
  stopToolButton,
  toolApprovals,
  unlimitedRounds,
} from "./dom.js";
import {
  canStopActiveTool,
  defaultModelForProvider,
  formatTime,
  humanizeStatus,
  isPhaseTwoRunning,
  latestProgressMessage,
  modelsForProvider,
  providerLabel,
  reportRowMetaText,
  selected,
  setAnalysisStatus,
} from "./utils.js";
import {decideToolRequest} from "./phase2.js";

// Repaints the entire phase-two panel: controls, status, approvals, progress.
export function renderPhaseTwo() {
  constraintsInput.value = state.analysisConstraints;
  const running = isPhaseTwoRunning();
  maxReasoningEffort.checked = state.maxReasoningEffort;
  maxReasoningEffort.disabled = running;
  unlimitedRounds.checked = state.unlimitedRounds;
  unlimitedRounds.disabled = running;
  bashMode.checked = state.bashMode;
  bashMode.disabled = running;
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

// Rebuilds the prior-reports picker for the selected event. `running` disables
// the controls while an analysis is in progress.
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

// Drops selected prior-report ids that no longer exist in the loaded list.
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

/** Prior-report ids selected for inclusion in the next phase-two request. */
export function selectedPriorReportIdsForEvent(eventId) {
  const selectedIds = state.priorReportIdsByEvent[eventId];
  return selectedIds ? [...selectedIds] : [];
}

// Lazily populates the analysis-type dropdown and syncs the current selection.
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

/** True when the "Custom" analysis type is currently selected. */
export function isCustomAnalysisSelected() {
  return state.analysisType === CUSTOM_ANALYSIS_TYPE;
}

// The Custom type cannot start without a goal; the tool set always has a value.
export function customAnalysisIncomplete() {
  return isCustomAnalysisSelected() && !state.customGoal.trim();
}

// Shows/populates the custom-analysis goal and tool-set fields when relevant.
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

// One-line summary of the configured approval mode shown next to the button.
function approvalSummary() {
  const mode = APPROVAL_MODES.find((item) => item.value === state.approvalMode) || APPROVAL_MODES[0];
  if (state.approvalMode === SMART_APPROVAL_MODE && state.approvalProvider && state.approvalModel) {
    return `${mode.summary} · ${providerLabel(state.approvalProvider)} / ${state.approvalModel}`;
  }
  return mode.summary;
}

// Opens the approval-configuration dialog, falling back to the `open` attribute
// when the native <dialog> showModal API is unavailable.
export function openApprovalDialog() {
  renderApprovalDialog();
  if (typeof approvalConfigDialog.showModal === "function") {
    approvalConfigDialog.showModal();
  } else {
    approvalConfigDialog.setAttribute("open", "");
  }
}

// Populates the approval dialog: radio selection and the smart-approver LLM
// dropdowns. The provider/model controls are only enabled for the smart mode.
export function renderApprovalDialog() {
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
export function approvalPayload() {
  if (state.approvalMode !== SMART_APPROVAL_MODE) {
    return {};
  }
  return {
    approval_provider: state.approvalProvider,
    approval_model: state.approvalModel,
    escalate_smart_rejections: state.escalateSmartRejections,
  };
}

// Reconciles the pending tool-approval cards with the current run state.
function renderToolApprovals() {
  const run = state.phase2Run;
  const pending = Array.isArray(run?.pending_tool_requests) ? run.pending_tool_requests : [];
  const pendingIds = new Set(pending.map((request) => request.request_id));
  // Keep existing pending cards alive across polling so focused inputs are not replaced.
  const existingCards = new Map(
    [...toolApprovals.children].map((card) => [card.dataset.requestId, card]),
  );

  pruneToolApprovalReasonDrafts(pendingIds);

  for (const request of pending) {
    const fingerprint = toolApprovalCardFingerprint(run, request);
    let card = existingCards.get(request.request_id);
    if (!card || card.dataset.renderFingerprint !== fingerprint) {
      const replacement = buildToolApprovalCard(run, request, fingerprint);
      if (card) {
        card.replaceWith(replacement);
      }
      card = replacement;
    }
    toolApprovals.append(card);
    existingCards.delete(request.request_id);
  }

  for (const staleCard of existingCards.values()) {
    staleCard.remove();
  }
}

function buildToolApprovalCard(run, request, fingerprint) {
  const card = document.createElement("div");
  card.className = "tool-approval";
  card.dataset.requestId = request.request_id;
  card.dataset.renderFingerprint = fingerprint;

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
    card.append(...buildManualApprovalControls(request));
  } else {
    card.append(renderAutomatedApprovalNotice(request));
  }
  return card;
}

function buildManualApprovalControls(request) {
  const reasonInput = document.createElement("input");
  reasonInput.type = "text";
  reasonInput.className = "tool-approval-reason";
  reasonInput.placeholder = "Optional reason for denial (returned to the analysis LLM)";
  reasonInput.value = state.toolApprovalReasonDrafts[request.request_id] || "";
  reasonInput.addEventListener("input", () => {
    state.toolApprovalReasonDrafts[request.request_id] = reasonInput.value;
  });

  const actions = document.createElement("div");
  actions.className = "tool-approval-actions";

  const deny = document.createElement("button");
  deny.type = "button";
  deny.textContent = "Deny";
  deny.addEventListener("click", () => decideToolRequest(
    request.request_id,
    false,
    reasonInput.value,
  ));

  const forwardDenialReason = smartReviewDenialReason(request);
  let forwardDenial = null;
  if (forwardDenialReason) {
    forwardDenial = document.createElement("button");
    forwardDenial.type = "button";
    forwardDenial.textContent = "Forward Denial";
    forwardDenial.title = "Deny using the smart approver's stated reason";
    forwardDenial.addEventListener("click", () => decideToolRequest(
      request.request_id,
      false,
      forwardDenialReason,
    ));
  }

  const approve = document.createElement("button");
  approve.type = "button";
  approve.textContent = "Approve";
  approve.addEventListener("click", () => decideToolRequest(request.request_id, true));

  actions.append(...[deny, forwardDenial, approve].filter(Boolean));
  return [reasonInput, actions];
}

// A card is only rebuilt when its fingerprint changes; this keeps it stable
// (and any focused input intact) across polls that do not affect the card.
function toolApprovalCardFingerprint(run, request) {
  return JSON.stringify({
    manualControls: shouldRenderManualApprovalControls(run, request),
    smartReview: request.smart_review || null,
    toolCall: request.tool_call || null,
  });
}

function pruneToolApprovalReasonDrafts(pendingIds) {
  for (const requestId of Object.keys(state.toolApprovalReasonDrafts)) {
    if (!pendingIds.has(requestId)) {
      delete state.toolApprovalReasonDrafts[requestId];
    }
  }
}

function smartReviewDenialReason(request) {
  const review = request.smart_review;
  if (!review || (review.approved && !review.error)) {
    return "";
  }
  return String(review.reasoning || "").trim();
}

// Decides whether a request needs manual approve/deny buttons, given the run's
// approval mode and (for smart mode) the smart approver's verdict.
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

// Renders the plain-text run progress log shown below the approvals.
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

// Describes the phase-two run status for the process indicator box.
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
