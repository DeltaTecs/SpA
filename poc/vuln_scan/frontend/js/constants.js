/**
 * Application-wide configuration constants.
 *
 * Everything in this module is static, immutable configuration shared across
 * the front end: the catalogue of analysis types, the tool sets the
 * "Custom" analysis exposes, the run-status groupings used to detect whether a
 * run is still active, and the MCP tool-approval modes.
 *
 * Some values intentionally mirror backend definitions. Where that is the case
 * an inline note marks the server-side module that must be kept in sync.
 */

/** Built-in vulnerability analysis types offered in the phase-two selector. */
export const ANALYSIS_TYPES = [
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
    description: "Define your own analysis goal and choose which MCP tool set to expose.",
  },
];
export const DEFAULT_ANALYSIS_TYPE = ANALYSIS_TYPES[0].label;
export const CUSTOM_ANALYSIS_TYPE = "Custom";

// Tool sets the Custom analysis type can enable. Must match CUSTOM_TOOL_SETS in
// the backend analysis_types module.
export const CUSTOM_TOOL_SETS = [
  "Network",
  "Domain",
  "HTTP/API",
  "Authentication",
  "Configuration",
  "Post-Recon General",
  "Database",
  "Database+Search",
  "Database+Search+Bash",
];
export const DEFAULT_CUSTOM_TOOL_SET = CUSTOM_TOOL_SETS[0];

/** Run statuses that mean a phase-two analysis is still in progress. */
export const ACTIVE_ANALYSIS_STATUSES = new Set(["queued", "running", "waiting_for_tool_approval"]);
/** Run statuses that mean a phase-one pre-scan is still in progress. */
export const ACTIVE_PRESCAN_STATUSES = new Set(["queued", "running"]);

/** Preferred default model per provider, applied when the model is available. */
export const PREFERRED_PROVIDER_MODELS = {
  deepseek: "deepseek-v4-pro",
};

/** MCP tool-approval modes shown in the approval-configuration dialog. */
export const APPROVAL_MODES = [
  {value: "manual", label: "Manual approval", summary: "Manual approval"},
  {value: "auto_db", label: "Auto approve database tools", summary: "Auto-approve database tools"},
  {value: "auto_all", label: "Auto approve all tools", summary: "Auto-approve all tools"},
  {value: "smart_non_db", label: "Smart approve non-db tools", summary: "Smart approve (non-db)"},
];
export const DEFAULT_APPROVAL_MODE = "manual";
export const AUTO_DB_APPROVAL_MODE = "auto_db";
export const AUTO_ALL_APPROVAL_MODE = "auto_all";
export const SMART_APPROVAL_MODE = "smart_non_db";
