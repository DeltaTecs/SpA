/**
 * Phase-two (vulnerability analysis) run lifecycle.
 *
 * Starts, aborts, and polls a single vulnerability-analysis run, handles
 * stopping an in-flight MCP tool, and submits approve/deny decisions for
 * pending MCP tool requests. Only one phase-two run is tracked at a time
 * (`state.phase2Run`).
 *
 * The phase-two *form* rendering (analysis type, approval dialog, tool-approval
 * cards, progress log) lives in render-analysis.js.
 */

import {state} from "./state.js";
import {
  canStopActiveTool,
  contextPayload,
  errorText,
  isPhaseTwoRunning,
  selected,
  setAnalysisStatus,
} from "./utils.js";
import {loadStoredReports} from "./api.js";
import {
  approvalPayload,
  customAnalysisIncomplete,
  isCustomAnalysisSelected,
  renderPhaseTwo,
  selectedPriorReportIdsForEvent,
} from "./render-analysis.js";

// Starts a vulnerability analysis for the selected event using the current
// phase-two form selections.
export async function startPhaseTwo() {
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
    state.toolApprovalReasonDrafts = {};
    state.phase2Run = await response.json();
    state.phase2RunId = state.phase2Run.run_id;
    renderPhaseTwo();
    schedulePhaseTwoPolling();
  } catch (error) {
    setAnalysisStatus(`Vulnerability analysis failed to start: ${error.message}`, true);
  }
}

// Requests cancellation of the active phase-two run.
export async function abortPhaseTwo() {
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

// Stops the MCP tool currently executing inside the active phase-two run.
export async function stopActiveTool() {
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

// Submits an approve/deny decision for a pending MCP tool request. The optional
// `reason` is returned to the analysis LLM when the request is denied.
export async function decideToolRequest(requestId, approved, reason = "") {
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
    delete state.toolApprovalReasonDrafts[requestId];
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

// Fetches the latest phase-two run snapshot; on completion it refreshes the
// event's stored reports so the new report appears immediately.
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
