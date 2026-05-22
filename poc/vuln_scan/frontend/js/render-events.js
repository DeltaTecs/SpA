/**
 * Rendering for the events-centric parts of the UI.
 *
 * Covers: the LLM configuration line, the event list, the detail-pane
 * switching between the event view and the stored-report viewer, the
 * phase-one (pre-scan) panel and its progress indicator, the stored-report
 * list, and the opened-report viewer with its condensed summary.
 *
 * Phase-two form rendering lives in render-analysis.js; this module calls into
 * it (`renderPhaseTwo`) because the event detail view embeds both phase panels.
 */

import {state} from "./state.js";
import {
  appDetailsFileName,
  condensedSummaryBody,
  condensedSummarySection,
  configText,
  deleteCondensedSummaryButton,
  detailPaneTitle,
  enablePhaseOneWebSearch,
  eventCount,
  eventDetail,
  eventList,
  modelSelect,
  phaseOnePanel,
  phaseOneTab,
  prescanProcess,
  prescanProcessText,
  providerSelect,
  refreshStoredReportsButton,
  report,
  reportDetail,
  selectedEvent,
  selectedReportBody,
  selectedReportLabel,
  selectedReportMeta,
  startButton,
  storedReportList,
  storedReportPosition,
  userIntendFileName,
  vulnerabilityPanel,
  vulnerabilityTab,
} from "./dom.js";
import {
  defaultModelForProvider,
  humanizeStatus,
  isEventRunning,
  latestProgressMessage,
  modelsForProvider,
  providerLabel,
  reportKey,
  reportRowMetaText,
  selected,
  selectedReport,
  setStatus,
  storedReportMetaText,
} from "./utils.js";
import {renderMarkdown} from "./markdown.js";
import {renderPhaseTwo} from "./render-analysis.js";
import {loadStoredReportsForSelectedEvent} from "./api.js";

// Switches the active phase tab and syncs the corresponding ARIA/active state.
export function setActiveTab(tab) {
  state.activeTab = tab;
  const phaseOneActive = tab === "phase1";
  phaseOneTab.classList.toggle("active", phaseOneActive);
  vulnerabilityTab.classList.toggle("active", !phaseOneActive);
  phaseOneTab.setAttribute("aria-selected", String(phaseOneActive));
  vulnerabilityTab.setAttribute("aria-selected", String(!phaseOneActive));
  phaseOnePanel.classList.toggle("active", phaseOneActive);
  vulnerabilityPanel.classList.toggle("active", !phaseOneActive);
}

// Repaints the provider/model selectors and the configuration summary line.
export function renderConfig() {
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

// Rebuilds the event list and refreshes everything that depends on selection.
export function renderEvents() {
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

// Chooses between the event view and the stored-report viewer in the detail
// pane, depending on whether a stored report is currently selected.
export function renderDetailPane() {
  const reportItem = selectedReport();
  const showingReport = Boolean(reportItem);
  detailPaneTitle.textContent = showingReport ? "Report" : "Event";
  eventDetail.classList.toggle("active", !showingReport);
  reportDetail.classList.toggle("active", showingReport);
  renderEventDetail();
  renderSelectedReport(reportItem);
}

// Repaints the event-detail view (pre-scan controls, result, phase-two panel).
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

// Repaints the stored-report viewer for the report opened in the detail pane.
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

// Shows or hides the condensed-summary section for the opened report.
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

// Rebuilds the stored-report list for the selected event.
export function renderStoredReports() {
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
