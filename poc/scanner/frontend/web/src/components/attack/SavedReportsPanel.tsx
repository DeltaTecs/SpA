import { useEffect, useState } from "react";
import { deleteScan, getScan, listAllScans } from "../../api/scans";
import type {
  PentestItemStatus,
  PentestJobStatus,
  ScanResultRecord,
  ScanResultSummary,
} from "../../api/types";
import { ReportCard } from "./ReportCard";
import { openToolScript } from "../toolscript/openToolScript";

interface SavedReportsPanelProps {
  /** db-api scan_type that scopes this queue's reports ("pentest" / "exploit"). */
  scanType: string;
  /** Changing this value forces a refetch (e.g. after a new report is persisted). */
  refreshToken?: unknown;
}

/** The single queued report carried by a persisted job snapshot, or null. */
function reportOf(record: ScanResultRecord): PentestItemStatus | null {
  const payload = record.payload as unknown as PentestJobStatus;
  return payload.items?.[0] ?? null;
}

function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleString();
}

function summaryLabel(row: ScanResultSummary, isLatest: boolean): string {
  const qualifier = row.model ?? row.provider ?? "";
  return (
    (isLatest ? "Latest · " : "") +
    `Recording ${row.recording_id} · ${formatTimestamp(row.created_at)}` +
    (qualifier ? ` · ${qualifier}` : "")
  );
}

/**
 * Browser for reports persisted to the db-api, so they survive a localStorage
 * reset (unlike the in-session Completed list). Lists every stored report of
 * ``scanType`` across recordings, renders the selected one via {@link ReportCard},
 * and supports deleting it. Mirrors the list→select→fetch flow of the Create Plan
 * tab's ScanHistorySelector.
 */
export function SavedReportsPanel({ scanType, refreshToken }: SavedReportsPanelProps) {
  const [history, setHistory] = useState<ScanResultSummary[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [record, setRecord] = useState<ScanResultRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  // (Re)load the list when the scan type or refresh token changes; auto-select
  // the latest so a report is shown without an extra click.
  useEffect(() => {
    let cancelled = false;
    listAllScans(scanType)
      .then((rows) => {
        if (cancelled) return;
        setHistory(rows);
        setSelectedId((current) =>
          current !== null && rows.some((r) => r.scan_result_id === current)
            ? current
            : rows[0]?.scan_result_id ?? null,
        );
      })
      .catch(() => {
        if (!cancelled) setHistory([]);
      });
    return () => {
      cancelled = true;
    };
  }, [scanType, refreshToken]);

  // Load the full snapshot for the selected report.
  useEffect(() => {
    if (selectedId === null) {
      setRecord(null);
      return;
    }
    let cancelled = false;
    setError(null);
    getScan(selectedId)
      .then((rec) => {
        if (!cancelled) setRecord(rec);
      })
      .catch((err) => {
        if (!cancelled) {
          setRecord(null);
          setError(err instanceof Error ? err.message : String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  async function removeSelected() {
    if (selectedId === null) return;
    if (!window.confirm("Delete this saved report? This cannot be undone.")) return;
    setDeleting(true);
    setError(null);
    try {
      await deleteScan(selectedId);
      const rows = await listAllScans(scanType);
      setHistory(rows);
      setSelectedId(rows[0]?.scan_result_id ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleting(false);
    }
  }

  const report = record ? reportOf(record) : null;

  return (
    <section className="panel">
      <h2 className="panel__title">
        Saved reports <span className="analysis-queue__count">{history.length}</span>
      </h2>
      <p className="muted">
        Reports persisted to the database. Unlike the Completed list, these survive a browser reset.
      </p>

      {history.length === 0 && <div className="muted">No saved reports yet.</div>}

      {history.length > 0 && (
        <div className="scan-history">
          <label className="recording-select">
            <span>Report</span>
            <select
              value={selectedId ?? ""}
              disabled={deleting}
              onChange={(event) => setSelectedId(Number(event.target.value) || null)}
            >
              {history.map((row, index) => (
                <option key={row.scan_result_id} value={row.scan_result_id}>
                  {summaryLabel(row, index === 0)}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="scan-history__delete"
            disabled={deleting || selectedId === null}
            onClick={() => void removeSelected()}
          >
            {deleting ? "Deleting…" : "Delete saved report"}
          </button>
        </div>
      )}

      {error && <span className="scan-history__error">{error}</span>}
      {report && (
        <>
          <div className="analysis-queue__result-actions">
            {selectedId !== null && (
              <button
                type="button"
                onClick={() =>
                  openToolScript({
                    source: "scan",
                    scanResultId: selectedId,
                    itemId: report.item_id,
                  })
                }
              >
                Tool script
              </button>
            )}
          </div>
          <ReportCard item={report} />
        </>
      )}
    </section>
  );
}
