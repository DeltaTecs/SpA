/**
 * Generic helpers shared across the front end.
 *
 * These are small, mostly pure functions with no rendering side effects: state
 * selectors, run-status predicates, provider/model lookups, status-line
 * writers, and value formatters. Keeping them in one dependency-light module
 * lets the feature modules (api, phase1, phase2, rendering) import what they
 * need without pulling in each other.
 */

import {state} from "./state.js";
import {
  ACTIVE_ANALYSIS_STATUSES,
  ACTIVE_PRESCAN_STATUSES,
  PREFERRED_PROVIDER_MODELS,
} from "./constants.js";
import {analysisStatus, statusLine} from "./dom.js";

// --- Selection helpers ------------------------------------------------------

/** Returns the currently selected event object, or null when none is selected. */
export function selected() {
  return state.events.find((event) => event.event_id === state.selectedEventId) || null;
}

/** Returns the stored report currently open in the detail pane, or null. */
export function selectedReport() {
  const event = selected();
  if (!event || !state.selectedReportKey) {
    return null;
  }
  return (state.storedReportsByEvent[event.event_id] || [])
    .find((reportItem) => reportKey(reportItem) === state.selectedReportKey) || null;
}

// Clears the selected report key if a freshly loaded report list no longer
// contains it, so the detail pane cannot point at a stale report.
export function syncSelectedReportForEvent(eventId) {
  if (eventId !== state.selectedEventId || !state.selectedReportKey) {
    return;
  }

  const reports = state.storedReportsByEvent[eventId] || [];
  if (!reports.some((reportItem) => reportKey(reportItem) === state.selectedReportKey)) {
    state.selectedReportKey = null;
  }
}

/** Stable key used to identify a stored report in selection state. */
export function reportKey(reportItem) {
  return String(reportItem.scan_id);
}

// --- Run-state predicates ---------------------------------------------------

export function isEventRunning(eventId) {
  return state.runningEventIds.has(eventId);
}

export function isPhaseTwoRunning() {
  return Boolean(state.phase2Run && ACTIVE_ANALYSIS_STATUSES.has(state.phase2Run.status));
}

export function hasActivePhaseOneRuns() {
  return Object.values(state.phase1RunsByEvent).some(
    (run) => ACTIVE_PRESCAN_STATUSES.has(run.status),
  );
}

export function canStopActiveTool() {
  const activeTool = state.phase2Run?.active_tool_execution;
  return Boolean(isPhaseTwoRunning() && activeTool?.status === "running");
}

// --- Provider / model helpers -----------------------------------------------

export function firstAvailableProvider() {
  return state.providers.find((provider) => provider.available) || null;
}

export function modelsForProvider(providerId) {
  const provider = state.providers.find((item) => item.id === providerId);
  return provider && Array.isArray(provider.models) ? provider.models : [];
}

// Picks a model for a provider, preferring (in order) a hard-coded preference,
// an explicit fallback, the provider's own default, then the first model.
export function defaultModelForProvider(providerId, fallbackModel = null) {
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

export function providerLabel(providerId) {
  return state.providers.find((provider) => provider.id === providerId)?.label || providerId || "provider";
}

// --- Status line writers ----------------------------------------------------

export function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.classList.toggle("error", isError);
}

export function setAnalysisStatus(message, isError = false) {
  analysisStatus.textContent = message;
  analysisStatus.classList.toggle("error", isError);
}

// --- Formatting helpers -----------------------------------------------------

export function formatTime(timestamp) {
  if (!timestamp) {
    return "--:--:--";
  }
  return new Date(timestamp * 1000).toLocaleTimeString();
}

export function humanizeStatus(status) {
  return String(status || "idle").replaceAll("_", " ");
}

/** Returns the message of the most recent progress entry for a run, or "". */
export function latestProgressMessage(run) {
  const progress = Array.isArray(run.progress) ? run.progress : [];
  return progress[progress.length - 1]?.message || "";
}

// Builds the Markdown shown for a stored phase-one summary record.
export function markdownFromSummary(summary) {
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

// --- Stored-report metadata formatting --------------------------------------

/** One-line provider/model (and tools) summary shown under a report row. */
export function reportRowMetaText(reportItem) {
  const provider = reportItem.llm_provider || "provider";
  const model = reportItem.llm_model || "model";
  const tools = reportItem.tools_used?.trim();
  return tools ? `${provider} / ${model}, tools: ${tools}` : `${provider} / ${model}`;
}

// Collapses the stored comma-separated tool list into unique names, keeping the
// order in which each tool first appears so a tool used repeatedly is shown once.
export function uniqueToolNames(toolsUsed) {
  const names = (toolsUsed || "")
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
  return [...new Set(names)];
}

// Formats a scan's wall-clock duration (seconds) as a compact human string,
// e.g. 45 -> "45s", 154 -> "2m 34s", 3725 -> "1h 2m". Returns a placeholder
// for reports recorded before duration tracking existed.
export function formatScanDuration(seconds) {
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

/** Multi-line metadata block shown above an opened stored report. */
export function storedReportMetaText(reportItem) {
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

// --- Request payload / network helpers --------------------------------------

// Collects the optional context-file overrides into a request payload fragment.
// Only files the user actually uploaded are included; otherwise the backend
// falls back to its configured defaults.
export function contextPayload() {
  const payload = {};

  if (state.appDetailsContent !== null) {
    payload.app_details_content = state.appDetailsContent;
  }
  if (state.userIntendContent !== null) {
    payload.user_intend_content = state.userIntendContent;
  }
  return payload;
}

// Extracts a human-readable error message from a failed fetch Response.
export async function errorText(response) {
  try {
    const data = await response.json();
    return data.detail || JSON.stringify(data);
  } catch {
    return `HTTP ${response.status}`;
  }
}
