import { apiGet } from "./client";
import type { RecordingInfo, RecordingStats } from "./types";

export function getRecordings(): Promise<RecordingInfo[]> {
  return apiGet<RecordingInfo[]>("/recordings");
}

export function getStats(recordingId: number): Promise<RecordingStats> {
  return apiGet<RecordingStats>(`/stats/${recordingId}`);
}
