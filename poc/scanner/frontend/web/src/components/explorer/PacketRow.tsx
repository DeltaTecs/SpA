import type { HttpSummary, PacketSummary } from "../../api/types";
import { colorsForKey } from "../../lib/colors";
import {
  directionLabel,
  directionShortLabel,
  formatBytes,
  formatEntropy,
  formatTimestamp,
} from "../../lib/format";

interface PacketRowProps {
  packet: PacketSummary;
  selected: boolean;
  colorOn: boolean;
  onSelect: (packetId: number) => void;
}

export function PacketRow({ packet, selected, colorOn, onSelect }: PacketRowProps) {
  const colors = colorOn ? colorsForKey(packet.association_key) : undefined;

  const timestamp = formatTimestamp(packet.timestamp);
  const protocols = packet.protocols.join(" > ");
  const remotePort =
    packet.remote_port === null || packet.remote_port === undefined
      ? ""
      : `:${packet.remote_port}`;
  const remote = packet.remote_ip
    ? `${packet.remote_ip}${remotePort}`
    : "-";
  const httpCell = formatHttpCell(packet.http);

  return (
    <tr
      className={`packet-row${selected ? " packet-row--selected" : ""}`}
      style={{
        backgroundColor: colors?.background,
        borderLeftColor: colors?.accent ?? "transparent",
      }}
      onClick={() => onSelect(packet.packet_id)}
    >
      <td className="mono packet-table__cell">{packet.number ?? packet.packet_id}</td>
      <td className="mono packet-table__cell" title={timestamp}>
        {timestamp}
      </td>
      <td className="center packet-table__cell" title={directionLabel(packet.from_local)}>
        {directionShortLabel(packet.from_local)}
      </td>
      <td className="packet-table__cell" title={protocols}>
        {protocols}
      </td>
      <td className="mono packet-table__cell" title={remote}>
        {remote}
      </td>
      <td className="mono packet-table__cell" title={httpCell}>
        {httpCell}
      </td>
      <td className="right packet-table__cell">{formatBytes(packet.payload_length)}</td>
      <td className="right packet-table__cell">{formatEntropy(packet.entropy)}</td>
    </tr>
  );
}

function formatHttpCell(http: HttpSummary | null): string {
  if (!http) return "";

  if (http.status_code !== null && http.status_code !== undefined) {
    return [String(http.status_code), http.status_text].filter(Boolean).join(" ");
  }

  return `${http.method ? `${http.method} ` : ""}${http.path ?? ""}`.trim();
}
