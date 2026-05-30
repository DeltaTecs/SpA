import { useEffect, useState } from "react";
import { getScan, listScans } from "../../api/scans";
import type { ScanResultRecord, ScanResultSummary } from "../../api/types";

interface ScanHistorySelectorProps {
  recordingId: number;
  scanType: string;
  /** scan_result_id currently shown, or null when displaying a live/current run. */
  selectedId: number | null;
  /** Changing this value forces a history refetch (e.g. after a new scan saves). */
  refreshToken?: unknown;
  disabled?: boolean;
  onSelect: (record: ScanResultRecord) => void;
}

/** Dropdown of a recording's stored scans; picking one loads its full snapshot. */
export function ScanHistorySelector({
  recordingId,
  scanType,
  selectedId,
  refreshToken,
  disabled,
  onSelect,
}: ScanHistorySelectorProps) {
  const [history, setHistory] = useState<ScanResultSummary[]>([]);

  useEffect(() => {
    let cancelled = false;
    listScans(recordingId, scanType)
      .then((rows) => {
        if (!cancelled) setHistory(rows);
      })
      .catch(() => {
        if (!cancelled) setHistory([]);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recordingId, scanType, refreshToken]);

  if (history.length === 0) return null;

  async function choose(value: string) {
    const id = Number(value);
    if (!id) return;
    onSelect(await getScan(id));
  }

  return (
    <label className="recording-select">
      <span>Saved scans</span>
      <select
        value={selectedId ?? ""}
        disabled={disabled}
        onChange={(event) => void choose(event.target.value)}
      >
        {selectedId === null && <option value="">Current run</option>}
        {history.map((row, index) => (
          <option key={row.scan_result_id} value={row.scan_result_id}>
            {index === 0 ? "Latest · " : ""}
            {formatTimestamp(row.created_at)}
            {row.model ? ` · ${row.model}` : row.provider ? ` · ${row.provider}` : ""}
          </option>
        ))}
      </select>
    </label>
  );
}

function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleString();
}
