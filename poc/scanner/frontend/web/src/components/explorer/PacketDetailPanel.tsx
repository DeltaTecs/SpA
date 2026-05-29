import { getPacket, getPayload } from "../../api/packets";
import type { HttpHeader, PacketDetail, PacketPayload } from "../../api/types";
import {
  directionLabel,
  formatBytes,
  formatEntropy,
  formatTimestamp,
} from "../../lib/format";
import { useFetch } from "../../lib/useFetch";
import { ErrorBanner } from "../common/ErrorBanner";
import { Loading } from "../common/Loading";
import { PayloadViewer } from "../common/PayloadViewer";

interface PacketDetailPanelProps {
  packetId: number;
  onClose: () => void;
}

export function PacketDetailPanel({ packetId, onClose }: PacketDetailPanelProps) {
  const detail = useFetch<PacketDetail>(() => getPacket(packetId), [packetId]);
  const payload = useFetch<PacketPayload>(() => getPayload(packetId), [packetId]);

  return (
    <section className="detail">
      <header className="detail__header">
        <h2>Packet #{packetId}</h2>
        <button type="button" className="detail__close" onClick={onClose} aria-label="Close">
          ×
        </button>
      </header>

      {detail.loading && <Loading />}
      {detail.error && <ErrorBanner message={detail.error} />}
      {detail.data && <PacketMeta detail={detail.data} />}
      {detail.data && <HeaderSection detail={detail.data} />}

      <h3 className="detail__section-title">Payload</h3>
      {payload.loading && <Loading />}
      {payload.error && <ErrorBanner message={payload.error} />}
      {payload.data && <PayloadViewer payload={payload.data} />}
    </section>
  );
}

function PacketMeta({ detail }: { detail: PacketDetail }) {
  const rows: [string, string][] = [
    ["Recording", String(detail.recording_id ?? "-")],
    ["Conversation", String(detail.conversation_id ?? "-")],
    ["Direction", directionLabel(detail.from_local)],
    ["Timestamp", formatTimestamp(detail.timestamp)],
    ["Protocols", detail.protocols.join(" › ") || "-"],
    ["Remote", detail.remote_ip ?? "-"],
    ["Payload", formatBytes(detail.payload_length)],
    ["Entropy", formatEntropy(detail.entropy)],
    ["Association", detail.association_key ?? "-"],
  ];
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div className="kv__row" key={k}>
          <dt>{k}</dt>
          <dd className="mono">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function HeaderSection({ detail }: { detail: PacketDetail }) {
  const { ip, tcp, udp, http } = detail.headers;
  return (
    <div className="detail__headers">
      {ip && (
        <HeaderBlock title="IP">
          <span>src {ip.src_addr ?? "-"}</span>
          <span>dst {ip.dst_addr ?? "-"}</span>
        </HeaderBlock>
      )}
      {tcp && (
        <HeaderBlock title="TCP">
          <span>src port {tcp.src_port ?? "-"}</span>
          <span>dst port {tcp.dst_port ?? "-"}</span>
          <span>len {tcp.length ?? "-"}</span>
        </HeaderBlock>
      )}
      {udp && (
        <HeaderBlock title="UDP">
          <span>src port {udp.src_port ?? "-"}</span>
          <span>dst port {udp.dst_port ?? "-"}</span>
          <span>len {udp.length ?? "-"}</span>
        </HeaderBlock>
      )}
      {http.map((header) => (
        <HttpHeaderBlock key={header.header_information_id} header={header} />
      ))}
    </div>
  );
}

function HttpHeaderBlock({ header }: { header: HttpHeader }) {
  const version = header.version == null ? "" : `/${header.version}`;
  const textHeader = header.text_header?.trim() ? header.text_header : null;

  return (
    <HeaderBlock title={`HTTP${version}`}>
      <span>header {header.header_information_id}</span>
      <span>stream {header.stream_id ?? "-"}</span>
      {textHeader ? (
        <pre className="detail__http-text">{textHeader}</pre>
      ) : (
        <span className="detail__muted">no stored header text</span>
      )}
    </HeaderBlock>
  );
}

function HeaderBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="header-block">
      <div className="header-block__title">{title}</div>
      <div className="header-block__body">{children}</div>
    </div>
  );
}
