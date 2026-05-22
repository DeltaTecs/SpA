/**
 * Backend communication and data loading.
 *
 * Every call to the `/api` endpoints that loads or mutates persisted data
 * lives here: LLM configuration, the event list, stored phase-one summaries
 * ("prescans"), stored phase-two reports ("scans"), and condensed-summary
 * deletion. Also includes reading user-supplied context files from disk.
 *
 * Each function folds its result into the shared `state` object and then asks
 * the rendering modules to repaint. Phase-one and phase-two *run* lifecycles
 * are handled separately in phase1.js and phase2.js.
 */

import {state} from "./state.js";
import {deleteCondensedSummaryButton} from "./dom.js";
import {
  defaultModelForProvider,
  errorText,
  firstAvailableProvider,
  markdownFromSummary,
  selected,
  selectedReport,
  setStatus,
  syncSelectedReportForEvent,
} from "./utils.js";
import {
  renderConfig,
  renderDetailPane,
  renderEvents,
  renderStoredReports,
} from "./render-events.js";

// Loads LLM provider configuration and seeds the analysis/approval selections.
// On failure the UI degrades to a "configuration unavailable" message.
export async function loadConfig() {
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

// Loads the event list, keeping the current selection when it still exists.
export async function loadEvents() {
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

// Loads stored phase-one summaries and indexes them by event id.
export async function loadPrescans() {
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

export async function loadStoredReportsForSelectedEvent(options = {}) {
  const event = selected();
  if (!event) {
    renderStoredReports();
    return;
  }
  await loadStoredReports(event.event_id, options);
}

export async function refreshStoredReportsForSelectedEvent() {
  await loadStoredReportsForSelectedEvent({force: true});
}

// Loads stored phase-two reports for an event. Cached results are reused unless
// `options.force` is set; concurrent loads for the same event are de-duplicated.
export async function loadStoredReports(eventId, options = {}) {
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

// Deletes the condensed summary attached to the currently opened report.
export async function deleteCondensedSummary() {
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

// Reads a user-selected context file from disk into state. `target` selects
// which context slot ("appDetails" or "userIntend") the content fills.
export async function readSelectedFile(input, target) {
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
