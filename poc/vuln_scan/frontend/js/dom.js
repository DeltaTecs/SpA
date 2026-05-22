/**
 * Cached references to the static DOM elements declared in index.html.
 *
 * Each element is looked up once, at module load, and exported by name so the
 * rest of the front end can refer to controls without repeating
 * `document.querySelector` calls. Modules are deferred, so this runs after the
 * document has been parsed and every query resolves.
 *
 * Elements are grouped to match the layout of index.html.
 */

// --- Events pane & stored-reports list --------------------------------------
export const eventList = document.querySelector("#eventList");
export const eventCount = document.querySelector("#eventCount");
export const storedReportPosition = document.querySelector("#storedReportPosition");
export const refreshStoredReportsButton = document.querySelector("#refreshStoredReportsButton");
export const storedReportList = document.querySelector("#storedReportList");

// --- Detail pane: shared chrome ---------------------------------------------
export const detailPaneTitle = document.querySelector("#detailPaneTitle");
export const eventDetail = document.querySelector("#eventDetail");
export const reportDetail = document.querySelector("#reportDetail");
export const selectedEvent = document.querySelector("#selectedEvent");

// --- Detail pane: stored-report viewer --------------------------------------
export const selectedReportLabel = document.querySelector("#selectedReport");
export const selectedReportMeta = document.querySelector("#selectedReportMeta");
export const selectedReportBody = document.querySelector("#selectedReportBody");
export const condensedSummarySection = document.querySelector("#condensedSummarySection");
export const condensedSummaryBody = document.querySelector("#condensedSummaryBody");
export const deleteCondensedSummaryButton = document.querySelector("#deleteCondensedSummaryButton");

// --- Top bar & LLM configuration --------------------------------------------
export const statusLine = document.querySelector("#statusLine");
export const report = document.querySelector("#report");
export const startButton = document.querySelector("#startButton");
export const enablePhaseOneWebSearch = document.querySelector("#enablePhaseOneWebSearch");
export const refreshButton = document.querySelector("#refreshButton");
export const configText = document.querySelector("#configText");
export const providerSelect = document.querySelector("#providerSelect");
export const modelSelect = document.querySelector("#modelSelect");

// --- Context file pickers ----------------------------------------------------
export const appDetailsBrowseButton = document.querySelector("#appDetailsBrowseButton");
export const appDetailsFileInput = document.querySelector("#appDetailsFileInput");
export const appDetailsFileName = document.querySelector("#appDetailsFileName");
export const userIntendBrowseButton = document.querySelector("#userIntendBrowseButton");
export const userIntendFileInput = document.querySelector("#userIntendFileInput");
export const userIntendFileName = document.querySelector("#userIntendFileName");

// --- Phase tabs --------------------------------------------------------------
export const phaseOneTab = document.querySelector("#phaseOneTab");
export const vulnerabilityTab = document.querySelector("#vulnerabilityTab");
export const phaseOnePanel = document.querySelector("#phaseOnePanel");
export const vulnerabilityPanel = document.querySelector("#vulnerabilityPanel");

// --- Phase two: analysis controls -------------------------------------------
export const analysisTypeSelect = document.querySelector("#analysisTypeSelect");
export const customAnalysisField = document.querySelector("#customAnalysisField");
export const customGoalInput = document.querySelector("#customGoalInput");
export const customToolSetSelect = document.querySelector("#customToolSetSelect");
export const startAnalysisButton = document.querySelector("#startAnalysisButton");
export const abortAnalysisButton = document.querySelector("#abortAnalysisButton");
export const stopToolButton = document.querySelector("#stopToolButton");
export const constraintsInput = document.querySelector("#constraintsInput");
export const maxReasoningEffort = document.querySelector("#maxReasoningEffort");
export const unlimitedRounds = document.querySelector("#unlimitedRounds");

// --- Phase two: approval configuration --------------------------------------
export const configureApprovalButton = document.querySelector("#configureApprovalButton");
export const approvalModeSummary = document.querySelector("#approvalModeSummary");
export const approvalConfigDialog = document.querySelector("#approvalConfigDialog");
export const approvalDialogCloseButton = document.querySelector("#approvalDialogCloseButton");
export const approvalLlmConfig = document.querySelector("#approvalLlmConfig");
export const approvalProviderSelect = document.querySelector("#approvalProviderSelect");
export const approvalModelSelect = document.querySelector("#approvalModelSelect");
export const escalateSmartRejections = document.querySelector("#escalateSmartRejections");
export const approvalModeRadios = document.querySelectorAll('input[name="approvalMode"]');

// --- Phase two: progress & prior reports ------------------------------------
export const analysisStatus = document.querySelector("#analysisStatus");
export const analysisProcess = document.querySelector("#analysisProcess");
export const analysisProcessText = document.querySelector("#analysisProcessText");
export const prescanProcess = document.querySelector("#prescanProcess");
export const prescanProcessText = document.querySelector("#prescanProcessText");
export const toolApprovals = document.querySelector("#toolApprovals");
export const analysisProgress = document.querySelector("#analysisProgress");
export const priorReportsList = document.querySelector("#priorReportsList");
export const priorReportsSummary = document.querySelector("#priorReportsSummary");
export const compactIncludedReports = document.querySelector("#compactIncludedReports");
