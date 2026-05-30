import { apiGet, apiPost } from "./client";
import type {
  ExchangeList,
  JobStatus,
  ProviderList,
  StartJobRequest,
  StartJobResponse,
  TaskTypeList,
  TerminationResult,
} from "./types";

// Interesting data exchanges come from the db-api (proxied under /api/*).
export function getExchanges(recordingId: number): Promise<ExchangeList> {
  return apiGet<ExchangeList>(`/recordings/${recordingId}/exchanges`);
}

// LLM planning endpoints live on the scanner backend (proxied under /api/plan/*).
export function getProviders(): Promise<ProviderList> {
  return apiGet<ProviderList>("/plan/providers");
}

export function getTaskTypes(): Promise<TaskTypeList> {
  return apiGet<TaskTypeList>("/plan/tasks");
}

export function startJob(request: StartJobRequest): Promise<StartJobResponse> {
  return apiPost<StartJobResponse>("/plan/jobs", request);
}

export function getJob(jobId: string): Promise<JobStatus> {
  return apiGet<JobStatus>(`/plan/jobs/${jobId}`);
}

// Terminate the analysis and kill all MCP tools (and their tool processes).
export function cancelJob(jobId: string): Promise<TerminationResult> {
  return apiPost<TerminationResult>(`/plan/jobs/${jobId}/cancel`, {});
}
