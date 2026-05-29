import type { PacketSummary } from "../../api/types";
import { PacketRow } from "./PacketRow";

interface PacketListProps {
  packets: PacketSummary[];
  selectedId: number | null;
  colorOn: boolean;
  onSelect: (packetId: number) => void;
}

export function PacketList({ packets, selectedId, colorOn, onSelect }: PacketListProps) {
  if (packets.length === 0) {
    return <div className="state">No packets match.</div>;
  }
  return (
    <table className="packet-table">
      <colgroup>
        <col className="packet-table__col-number" />
        <col className="packet-table__col-time" />
        <col className="packet-table__col-direction" />
        <col className="packet-table__col-protocols" />
        <col className="packet-table__col-remote" />
        <col className="packet-table__col-http" />
        <col className="packet-table__col-payload" />
        <col className="packet-table__col-entropy" />
      </colgroup>
      <thead>
        <tr>
          <th>#</th>
          <th>Time (UTC)</th>
          <th>Dir</th>
          <th>Protocols</th>
          <th>Remote</th>
          <th>HTTP</th>
          <th className="right">Payload</th>
          <th className="right">Entropy</th>
        </tr>
      </thead>
      <tbody>
        {packets.map((packet) => (
          <PacketRow
            key={packet.packet_id}
            packet={packet}
            selected={packet.packet_id === selectedId}
            colorOn={colorOn}
            onSelect={onSelect}
          />
        ))}
      </tbody>
    </table>
  );
}
