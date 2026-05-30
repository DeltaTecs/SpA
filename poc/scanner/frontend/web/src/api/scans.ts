import { ApiError, apiGet } from "./client";
import type { ScanResultRecord, ScanResultSummary } from "./types";

/** Scan types persisted by the scanner-backend (see db-api scan_result.scan_type). */
export const VULNERABILITY_SCAN_TYPE = "vulnerability_checks";
export const PENTEST_SCAN_TYPE = "pentest";

/** Most recent stored scan of a type for a recording, or null when none exists. */
export async function getLatestScan(
  recordingId: number,
  scanType: string,
): Promise<ScanResultRecord | null> {
  try {
    return await apiGet<ScanResultRecord>(
      `/recordings/${recordingId}/scans/latest?scan_type=${encodeURIComponent(scanType)}`,
    );
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

/** Stored scan history (metadata only) for a recording and type, newest first. */
export function listScans(
  recordingId: number,
  scanType: string,
): Promise<ScanResultSummary[]> {
  return apiGet<ScanResultSummary[]>(
    `/recordings/${recordingId}/scans?scan_type=${encodeURIComponent(scanType)}`,
  );
}

/** A single stored scan, including its full snapshot payload. */
export function getScan(scanResultId: number): Promise<ScanResultRecord> {
  return apiGet<ScanResultRecord>(`/scans/${scanResultId}`);
}
