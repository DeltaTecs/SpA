import { useState } from "react";
import { listPackets } from "../api/packets";
import type { PacketPage } from "../api/types";
import { ColorToggle } from "../components/explorer/ColorToggle";
import { PacketDetailPanel } from "../components/explorer/PacketDetailPanel";
import { PacketList } from "../components/explorer/PacketList";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { Loading } from "../components/common/Loading";
import { useFetch } from "../lib/useFetch";

const DEFAULT_RECORDING_ID = 1;
const PAGE_SIZE = 100;

export function ExplorerPage() {
  const [offset, setOffset] = useState(0);
  const [colorOn, setColorOn] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const page = useFetch<PacketPage>(
    () => listPackets({ recording_id: DEFAULT_RECORDING_ID, limit: PAGE_SIZE, offset }),
    [offset],
  );

  const total = page.data?.total ?? 0;
  const shownFrom = total === 0 ? 0 : offset + 1;
  const shownTo = Math.min(offset + PAGE_SIZE, total);
  const canPrev = offset > 0;
  const canNext = offset + PAGE_SIZE < total;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Packet Explorer</h1>
        <div className="toolbar">
          <ColorToggle enabled={colorOn} onChange={setColorOn} />
          <div className="pager">
            <button disabled={!canPrev} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
              ‹ Prev
            </button>
            <span className="pager__label">
              {shownFrom.toLocaleString()}–{shownTo.toLocaleString()} of {total.toLocaleString()}
            </span>
            <button disabled={!canNext} onClick={() => setOffset((o) => o + PAGE_SIZE)}>
              Next ›
            </button>
          </div>
        </div>
      </header>

      <div className={`explorer${selectedId !== null ? " explorer--split" : ""}`}>
        <div className="explorer__list">
          {page.loading && <Loading label="Loading packets…" />}
          {page.error && <ErrorBanner message={page.error} />}
          {page.data && (
            <PacketList
              packets={page.data.items}
              selectedId={selectedId}
              colorOn={colorOn}
              onSelect={setSelectedId}
            />
          )}
        </div>
        {selectedId !== null && (
          <div className="explorer__detail">
            <PacketDetailPanel packetId={selectedId} onClose={() => setSelectedId(null)} />
          </div>
        )}
      </div>
    </div>
  );
}
