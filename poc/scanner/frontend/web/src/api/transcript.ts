import { apiGet, buildQuery } from "./client";
import type { TranscriptDoc } from "./types";

// Recorded tool-use transcripts. Live (in-memory) transcripts come from the
// scanner backend via the /api/plan proxy; persisted ones come from the db-api
// (scan_result side table) via the /api proxy. All share the TranscriptDoc shape.
//
// `itemId` is always passed as a query param because item ids are opaque strings
// that can contain '/' (e.g. "http:GET|/api/users|id"), which would break a path
// segment.

/** Live transcript of one completed Analysis Queue (pentest) item. */
export function getPentestTranscript(jobId: string, itemId: string): Promise<TranscriptDoc> {
  return apiGet<TranscriptDoc>(`/plan/pentest/jobs/${jobId}/transcript${buildQuery({ item_id: itemId })}`);
}

/** Live transcript of one completed Exploit Queue item. */
export function getExploitTranscript(jobId: string, itemId: string): Promise<TranscriptDoc> {
  return apiGet<TranscriptDoc>(`/plan/exploit/jobs/${jobId}/transcript${buildQuery({ item_id: itemId })}`);
}

/** Ephemeral transcript of one guided-analysis turn (lost on backend restart). */
export function getGuidedTranscript(jobId: string): Promise<TranscriptDoc> {
  return apiGet<TranscriptDoc>(`/plan/guided/turns/${jobId}/transcript`);
}

/** Persisted transcript of one item of a saved scan report (db-api). */
export function getScanTranscript(scanResultId: number, itemId: string): Promise<TranscriptDoc> {
  return apiGet<TranscriptDoc>(`/scans/${scanResultId}/transcript${buildQuery({ item_id: itemId })}`);
}
