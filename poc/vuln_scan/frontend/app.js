const state = {
  events: [],
  selectedEventId: null,
};

const eventList = document.querySelector("#eventList");
const eventCount = document.querySelector("#eventCount");
const selectedEvent = document.querySelector("#selectedEvent");
const statusLine = document.querySelector("#statusLine");
const report = document.querySelector("#report");
const startButton = document.querySelector("#startButton");
const refreshButton = document.querySelector("#refreshButton");
const configText = document.querySelector("#configText");

refreshButton.addEventListener("click", loadEvents);
startButton.addEventListener("click", startPhaseOne);

loadConfig();
loadEvents();

async function loadConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const config = await response.json();
    configText.textContent = `Provider ${config.provider}, model ${config.model}`;
  } catch (error) {
    configText.textContent = "Backend configuration unavailable.";
  }
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
    setStatus(state.events.length ? "Select an event and start phase 1." : "No events found.");
  } catch (error) {
    setStatus(`Could not load events: ${error.message}`, true);
  }
}

async function startPhaseOne() {
  const event = selected();
  if (!event) {
    return;
  }

  startButton.disabled = true;
  refreshButton.disabled = true;
  report.textContent = "";
  setStatus(`Running phase 1 for event ${event.event_id}...`);

  try {
    const response = await fetch("/api/phase1", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({event_id: event.event_id}),
    });
    if (!response.ok) {
      throw new Error(await errorText(response));
    }
    const result = await response.json();
    report.textContent = result.markdown || "";
    setStatus(`Phase 1 complete for event ${event.event_id}.`);
  } catch (error) {
    setStatus(`Phase 1 failed: ${error.message}`, true);
  } finally {
    refreshButton.disabled = false;
    renderEvents();
  }
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
    meta.textContent = `${event.packet_count} packets, recordings ${recordings}`;

    button.append(title, meta);
    eventList.append(button);
  }

  const event = selected();
  startButton.disabled = !event;
  selectedEvent.textContent = event
    ? `Selected event ${event.event_id}: ${event.description || "(no description)"}`
    : "Select an event.";
}

function selected() {
  return state.events.find((event) => event.event_id === state.selectedEventId) || null;
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.classList.toggle("error", isError);
}

async function errorText(response) {
  try {
    const data = await response.json();
    return data.detail || JSON.stringify(data);
  } catch {
    return `HTTP ${response.status}`;
  }
}
