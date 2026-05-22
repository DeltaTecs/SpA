/**
 * Application entry point.
 *
 * This is the module referenced by index.html (`<script type="module">`). It
 * pulls together every feature module, wires DOM controls to their handlers,
 * and kicks off the initial data loads. It contains no business logic of its
 * own — only event-listener registration and bootstrapping.
 */

import {state} from "./state.js";
import {
  abortAnalysisButton,
  analysisTypeSelect,
  appDetailsBrowseButton,
  appDetailsFileInput,
  approvalConfigDialog,
  approvalDialogCloseButton,
  approvalModelSelect,
  approvalModeRadios,
  approvalProviderSelect,
  compactIncludedReports,
  configureApprovalButton,
  constraintsInput,
  customGoalInput,
  customToolSetSelect,
  deleteCondensedSummaryButton,
  enablePhaseOneWebSearch,
  escalateSmartRejections,
  maxReasoningEffort,
  modelSelect,
  phaseOneTab,
  providerSelect,
  refreshButton,
  refreshStoredReportsButton,
  startAnalysisButton,
  startButton,
  stopToolButton,
  unlimitedRounds,
  userIntendBrowseButton,
  userIntendFileInput,
  vulnerabilityTab,
} from "./dom.js";
import {defaultModelForProvider} from "./utils.js";
import {
  deleteCondensedSummary,
  loadConfig,
  loadEvents,
  loadPrescans,
  readSelectedFile,
  refreshStoredReportsForSelectedEvent,
} from "./api.js";
import {startPhaseOne} from "./phase1.js";
import {abortPhaseTwo, startPhaseTwo, stopActiveTool} from "./phase2.js";
import {renderConfig, renderDetailPane, setActiveTab} from "./render-events.js";
import {openApprovalDialog, renderApprovalDialog, renderPhaseTwo} from "./render-analysis.js";

// --- DOM event wiring -------------------------------------------------------

refreshButton.addEventListener("click", loadEvents);
deleteCondensedSummaryButton.addEventListener("click", deleteCondensedSummary);
refreshStoredReportsButton.addEventListener("click", () => refreshStoredReportsForSelectedEvent());
startButton.addEventListener("click", startPhaseOne);
enablePhaseOneWebSearch.addEventListener("change", () => {
  state.enablePhaseOneWebSearch = enablePhaseOneWebSearch.checked;
  renderDetailPane();
});
phaseOneTab.addEventListener("click", () => setActiveTab("phase1"));
vulnerabilityTab.addEventListener("click", () => setActiveTab("phase2"));
analysisTypeSelect.addEventListener("change", () => {
  state.analysisType = analysisTypeSelect.value;
  renderPhaseTwo();
});
customGoalInput.addEventListener("input", () => {
  state.customGoal = customGoalInput.value;
  renderPhaseTwo();
});
customToolSetSelect.addEventListener("change", () => {
  state.customToolSet = customToolSetSelect.value;
});
startAnalysisButton.addEventListener("click", startPhaseTwo);
abortAnalysisButton.addEventListener("click", abortPhaseTwo);
stopToolButton.addEventListener("click", stopActiveTool);
configureApprovalButton.addEventListener("click", openApprovalDialog);
approvalDialogCloseButton.addEventListener("click", () => approvalConfigDialog.close());
approvalConfigDialog.addEventListener("close", renderPhaseTwo);
approvalConfigDialog.addEventListener("click", (event) => {
  if (event.target === approvalConfigDialog) {
    approvalConfigDialog.close();
  }
});
for (const radio of approvalModeRadios) {
  radio.addEventListener("change", () => {
    if (radio.checked) {
      state.approvalMode = radio.value;
      renderApprovalDialog();
    }
  });
}
approvalProviderSelect.addEventListener("change", () => {
  state.approvalProvider = approvalProviderSelect.value;
  state.approvalModel = defaultModelForProvider(state.approvalProvider);
  renderApprovalDialog();
});
approvalModelSelect.addEventListener("change", () => {
  state.approvalModel = approvalModelSelect.value;
});
escalateSmartRejections.addEventListener("change", () => {
  state.escalateSmartRejections = escalateSmartRejections.checked;
});
compactIncludedReports.addEventListener("change", () => {
  state.compactIncludedReports = compactIncludedReports.checked;
  renderPhaseTwo();
});
maxReasoningEffort.addEventListener("change", () => {
  state.maxReasoningEffort = maxReasoningEffort.checked;
  renderPhaseTwo();
});
unlimitedRounds.addEventListener("change", () => {
  state.unlimitedRounds = unlimitedRounds.checked;
  renderPhaseTwo();
});
constraintsInput.addEventListener("input", () => {
  state.analysisConstraints = constraintsInput.value;
  renderPhaseTwo();
});
providerSelect.addEventListener("change", () => {
  state.selectedProvider = providerSelect.value;
  state.selectedModel = defaultModelForProvider(state.selectedProvider);
  renderConfig();
});
modelSelect.addEventListener("change", () => {
  state.selectedModel = modelSelect.value;
  renderConfig();
});
appDetailsBrowseButton.addEventListener("click", () => appDetailsFileInput.click());
userIntendBrowseButton.addEventListener("click", () => userIntendFileInput.click());
appDetailsFileInput.addEventListener("change", () => readSelectedFile(appDetailsFileInput, "appDetails"));
userIntendFileInput.addEventListener("change", () => readSelectedFile(userIntendFileInput, "userIntend"));

// --- Initial data load ------------------------------------------------------

loadConfig();
loadEvents();
loadPrescans();
