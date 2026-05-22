/**
 * Phase-one (pre-scan) run lifecycle.
 *
 * Starts a pre-scan for the selected event, then polls every active pre-scan
 * run until all of them reach a terminal state. A single shared timer drives
 * every run so multiple events can be pre-scanned concurrently.
 */

import {state} from "./state.js";
import {ACTIVE_PRESCAN_STATUSES} from "./constants.js";
import {
  contextPayload,
  errorText,
  hasActivePhaseOneRuns,
  isEventRunning,
  providerLabel,
  selected,
  setStatus,
} from "./utils.js";
import {renderConfig, renderDetailPane, renderEvents} from "./render-events.js";

// Starts a pre-scan for the currently selected event.
export async function startPhaseOne() {
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

// Polls every active pre-scan run in parallel and stops the timer once they
// have all reached a terminal state.
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
