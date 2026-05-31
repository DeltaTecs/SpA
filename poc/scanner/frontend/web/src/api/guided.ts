import { apiGet, apiPost } from "./client";
import type {
  GuidedTurnStatus,
  ReviewDecisionRequest,
  StartGuidedTurnRequest,
  StartGuidedTurnResponse,
  TerminationResult,
} from "./types";

// Guided-analysis endpoints live on the scanner backend, reached through the
// existing /api/plan proxy mount (which forwards to the backend's /guided/* routes).

export function startGuidedTurn(
  request: StartGuidedTurnRequest,
): Promise<StartGuidedTurnResponse> {
  return apiPost<StartGuidedTurnResponse>("/plan/guided/turns", request);
}

export function getGuidedTurn(jobId: string): Promise<GuidedTurnStatus> {
  return apiGet<GuidedTurnStatus>(`/plan/guided/turns/${jobId}`);
}

// Terminate the turn and kill all MCP tools (and their tool processes).
export function cancelGuidedTurn(jobId: string): Promise<TerminationResult> {
  return apiPost<TerminationResult>(`/plan/guided/turns/${jobId}/cancel`, {});
}

export function submitGuidedReview(
  jobId: string,
  reviewId: string,
  decision: ReviewDecisionRequest,
): Promise<{ resolved: boolean }> {
  return apiPost<{ resolved: boolean }>(
    `/plan/guided/turns/${jobId}/reviews/${reviewId}`,
    decision,
  );
}
