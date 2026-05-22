/**
 * Shared, mutable application state.
 *
 * Every module imports this single `state` object by reference and mutates it
 * directly; there is no setter layer. Rendering modules read from `state` to
 * build the DOM, and event handlers / API calls write to it. Because the object
 * identity never changes, mutations made in one module are immediately visible
 * in all others.
 */

import {
  DEFAULT_ANALYSIS_TYPE,
  DEFAULT_APPROVAL_MODE,
  DEFAULT_CUSTOM_TOOL_SET,
} from "./constants.js";

export const state = {
  events: [],
  selectedEventId: null,
  selectedReportKey: null,
  providers: [],
  selectedProvider: null,
  selectedModel: null,
  appDetailsFileName: "",
  appDetailsContent: null,
  userIntendFileName: "",
  userIntendContent: null,
  runningEventIds: new Set(),
  results: {},
  configError: null,
  activeTab: "phase1",
  analysisType: DEFAULT_ANALYSIS_TYPE,
  analysisConstraints: "",
  customGoal: "",
  customToolSet: DEFAULT_CUSTOM_TOOL_SET,
  enablePhaseOneWebSearch: false,
  approvalMode: DEFAULT_APPROVAL_MODE,
  approvalProvider: null,
  approvalModel: null,
  escalateSmartRejections: true,
  suggestImprovement: false,
  phase2RunId: null,
  phase2Run: null,
  phase2PollTimer: null,
  toolApprovalReasonDrafts: {},
  phase1RunsByEvent: {},
  phase1PollTimer: null,
  storedReportsByEvent: {},
  loadingReportEventIds: new Set(),
  reportErrorsByEvent: {},
  priorReportIdsByEvent: {},
  compactIncludedReports: true,
  maxReasoningEffort: false,
  unlimitedRounds: false,
  bashMode: false,
};
