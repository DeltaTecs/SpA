import { useEffect, useState } from "react";
import { getPacket, getPayload } from "../../api/packets";
import type { HttpHeader, PacketDetail, PacketPayload } from "../../api/types";
import { directionLabel, formatBytes, formatTimestamp } from "../../lib/format";
import { useFetch } from "../../lib/useFetch";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { PayloadViewer } from "../common/PayloadViewer";
import type { EditableExchange } from "./types";

interface ExchangeEvidenceProps {
  item: EditableExchange;
}

export function ExchangeEvidence({ item }: ExchangeEvidenceProps) {
  const packetIds = item.representative_packet_ids;
  if (packetIds.length === 0) {
    return <div className="muted">No representative packets are attached to this exchange.</div>;
  }
  return <ExchangeEvidenceContent item={item} packetIds={packetIds} />;
}

function ExchangeEvidenceContent({
  item,
  packetIds,
}: {
  item: EditableExchange;
  packetIds: number[];
}) {
  const packetIdsKey = packetIds.join("|");
  const [selectedPacketId, setSelectedPacketId] = useState(packetIds[0]);

  useEffect(() => {
    if (!packetIds.includes(selectedPacketId)) {
      setSelectedPacketId(packetIds[0]);
    }
  }, [packetIds, packetIdsKey, selectedPacketId]);

  const detail = useFetch<PacketDetail>(() => getPacket(selectedPacketId), [selectedPacketId]);
  const payload = useFetch<PacketPayload>(() => getPayload(selectedPacketId), [selectedPacketId]);

  return (
    <section className="exchange-evidence" aria-label="Representative packet evidence">
      <div className="exchange-evidence__head">
        <h3>Packet evidence</h3>
        <div className="exchange-evidence__tabs" role="tablist" aria-label="Representative packets">
          {packetIds.map((packetId, index) => (
            <button
              key={packetId}
              type="button"
              className={`tab${packetId === selectedPacketId ? " tab--active" : ""}`}
              onClick={() => setSelectedPacketId(packetId)}
              role="tab"
              aria-selected={packetId === selectedPacketId}
            >
              {packetTabLabel(item, packetId, index)}
            </button>
          ))}
        </div>
      </div>

      {detail.loading && <Loading label="Loading packet..." />}
      {detail.error && <ErrorBanner message={detail.error} />}
      {detail.data && (
        <>
          <PacketMeta detail={detail.data} />
          <HttpHeaderDetails headers={detail.data.headers.http} />
        </>
      )}

      <details className="exchange-evidence__details" open>
        <summary>Application payload</summary>
        {payload.loading && <Loading label="Loading payload..." />}
        {payload.error && <ErrorBanner message={payload.error} />}
        {payload.data && <PayloadViewer payload={payload.data} />}
      </details>
    </section>
  );
}

function PacketMeta({ detail }: { detail: PacketDetail }) {
  const rows: [string, string][] = [
    ["Direction", directionLabel(detail.from_local)],
    ["Timestamp", formatTimestamp(detail.timestamp)],
    ["Protocols", detail.protocols.join(" > ") || "-"],
    ["Payload", formatBytes(detail.payload_length)],
  ];

  return (
    <dl className="kv exchange-evidence__meta">
      {rows.map(([label, value]) => (
        <div className="kv__row" key={label}>
          <dt>{label}</dt>
          <dd className="mono">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function HttpHeaderDetails({ headers }: { headers: HttpHeader[] }) {
  if (headers.length === 0) {
    return (
      <details className="exchange-evidence__details">
        <summary>HTTP header</summary>
        <div className="state">No stored HTTP header text.</div>
      </details>
    );
  }

  return (
    <div className="exchange-evidence__http">
      {headers.map((header, index) => (
        <HttpHeaderDetail
          key={header.header_information_id}
          header={header}
          defaultOpen={index === 0}
        />
      ))}
    </div>
  );
}

function HttpHeaderDetail({
  header,
  defaultOpen,
}: {
  header: HttpHeader;
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const version = header.version == null ? "" : `/${header.version}`;
  const textHeader = header.text_header?.trim();

  useEffect(() => {
    setOpen(defaultOpen);
  }, [defaultOpen, header.header_information_id]);

  return (
    <details
      className="exchange-evidence__details"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>HTTP{version} header</summary>
      <div className="exchange-evidence__header-meta mono">
        <span>header {header.header_information_id}</span>
        <span>stream {header.stream_id ?? "-"}</span>
      </div>
      {textHeader ? (
        <pre className="exchange-evidence__pre mono">{textHeader}</pre>
      ) : (
        <div className="state">No stored HTTP header text.</div>
      )}
    </details>
  );
}

function packetTabLabel(item: EditableExchange, packetId: number, index: number): string {
  if (item.kind === "http_pair") {
    if (index === 0) return `Request #${packetId}`;
    if (index === 1) return `Response #${packetId}`;
  }
  return `Packet #${packetId}`;
}
