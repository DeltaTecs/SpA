import { useEffect, useState } from "react";
import { deleteScan, getScan, listScans } from "../../api/scans";
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
  onDelete: (replacement: ScanResultRecord | null) => void;
}

/** Dropdown of stored scans, with deletion of the selected/latest snapshot. */
export function ScanHistorySelector({
  recordingId,
  scanType,
  selectedId,
  refreshToken,
  disabled,
  onSelect,
  onDelete,
}: ScanHistorySelectorProps) {
  const [history, setHistory] = useState<ScanResultSummary[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDeleteError(null);
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

  async function removeSavedScan() {
    const target = history.find((row) => row.scan_result_id === selectedId) ?? history[0];
    if (!target) return;
    const label = selectedId === null ? "latest" : "selected";
    if (!window.confirm(`Delete the ${label} saved scan result? This cannot be undone.`)) return;

    setDeleting(true);
    setDeleteError(null);
    try {
      await deleteScan(target.scan_result_id);
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
      setDeleting(false);
      return;
    }

    setHistory((rows) => rows.filter((row) => row.scan_result_id !== target.scan_result_id));
    onDelete(null);
    try {
      const rows = await listScans(recordingId, scanType);
      setHistory(rows);
      if (rows[0]) onDelete(await getScan(rows[0].scan_result_id));
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      setDeleteError(`Deleted scan, but could not reload saved scans: ${detail}`);
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="scan-history">
      <label className="recording-select">
        <span>Saved scans</span>
        <select
          value={selectedId ?? ""}
          disabled={disabled || deleting}
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
      <button
        type="button"
        className="scan-history__delete"
        disabled={disabled || deleting}
        onClick={() => void removeSavedScan()}
        title={`Delete the ${selectedId === null ? "latest" : "selected"} saved scan result`}
      >
        {deleting ? "Deleting..." : "Delete saved scan"}
      </button>
      {deleteError && <span className="scan-history__error">{deleteError}</span>}
    </div>
  );
}

function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleString();
}
