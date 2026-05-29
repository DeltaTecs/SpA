import type { PacketSummary } from "../../api/types";
import { accentForKey, colorForKey } from "../../lib/colors";
import {
  directionArrow,
  directionLabel,
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
  const background = colorOn ? colorForKey(packet.association_key) : undefined;
  const accent = colorOn ? accentForKey(packet.association_key) : "transparent";

  const remote = packet.remote_ip
    ? `${packet.remote_ip}${packet.remote_port ? `:${packet.remote_port}` : ""}`
    : "-";
  const httpCell = packet.http
    ? `${packet.http.method ? packet.http.method + " " : ""}${packet.http.path ?? ""}`.trim()
    : "";

  return (
    <tr
      className={`packet-row${selected ? " packet-row--selected" : ""}`}
      style={{ backgroundColor: background, borderLeftColor: accent }}
      onClick={() => onSelect(packet.packet_id)}
    >
      <td className="mono">{packet.number ?? packet.packet_id}</td>
      <td className="mono nowrap">{formatTimestamp(packet.timestamp)}</td>
      <td className="center" title={directionLabel(packet.from_local)}>
        {directionArrow(packet.from_local)}
      </td>
      <td>{packet.protocols.join(" › ")}</td>
      <td className="mono nowrap">{remote}</td>
      <td className="mono truncate" title={httpCell}>
        {httpCell}
      </td>
      <td className="right">{formatBytes(packet.payload_length)}</td>
      <td className="right">{formatEntropy(packet.entropy)}</td>
    </tr>
  );
}
