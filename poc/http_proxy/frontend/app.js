"use strict";

// nginx reverse-proxies "/api/" to the proxy's configuration API, so the
// browser only ever talks to this (same-origin) relative path.
const CONFIG_ENDPOINT = "api/config";

const form = document.getElementById("config-form");
const userAgentInput = document.getElementById("user-agent");
const rateLimitInput = document.getElementById("rate-limit");
const burstInput = document.getElementById("burst");
const saveButton = document.getElementById("save-button");
const reloadButton = document.getElementById("reload-button");
const statusBadge = document.getElementById("status");
const message = document.getElementById("message");

function setStatus(text, modifier) {
  statusBadge.textContent = text;
  statusBadge.className = `status status--${modifier}`;
}

function showMessage(text, modifier) {
  message.textContent = text;
  message.className = modifier ? `message message--${modifier}` : "message";
}

function applyConfig(config) {
  userAgentInput.value = config.user_agent ?? "";
  rateLimitInput.value = config.rate_limit_per_minute ?? 0;
  burstInput.value = config.rate_limit_burst ?? 1;
}

// Load the current configuration and populate the form.
async function loadConfig() {
  setStatus("Connecting…", "loading");
  try {
    const response = await fetch(CONFIG_ENDPOINT, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    applyConfig(await response.json());
    setStatus("Connected", "ok");
    showMessage("", "");
  } catch (error) {
    setStatus("Unreachable", "error");
    showMessage(`Could not load configuration: ${error.message}`, "error");
  }
}

// Validate and persist the form values.
async function saveConfig(event) {
  event.preventDefault();
  const payload = {
    user_agent: userAgentInput.value.trim(),
    rate_limit_per_minute: Number(rateLimitInput.value),
    rate_limit_burst: Number(burstInput.value),
  };

  saveButton.disabled = true;
  showMessage("Saving…", "info");
  try {
    const response = await fetch(CONFIG_ENDPOINT, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    // The API returns a JSON body for both success and error responses.
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `HTTP ${response.status}`);
    }
    applyConfig(body);
    setStatus("Connected", "ok");
    showMessage("Configuration saved.", "ok");
  } catch (error) {
    showMessage(`Could not save configuration: ${error.message}`, "error");
  } finally {
    saveButton.disabled = false;
  }
}

form.addEventListener("submit", saveConfig);
reloadButton.addEventListener("click", loadConfig);

loadConfig();
