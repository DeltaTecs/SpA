import type { AppProtocolFilter } from "../../api/packets";

export type PacketProtocolFilter = AppProtocolFilter | "all";

export interface PacketExplorerFilters {
  hasClearPayload: boolean;
  hasHttpHeaderText: boolean;
  appProtocol: PacketProtocolFilter;
}

export const DEFAULT_PACKET_FILTERS: PacketExplorerFilters = {
  hasClearPayload: false,
  hasHttpHeaderText: false,
  appProtocol: "all",
};

interface PacketFiltersProps {
  filters: PacketExplorerFilters;
  activeCount: number;
  onChange: (filters: PacketExplorerFilters) => void;
  onReset: () => void;
}

export function PacketFilters({
  filters,
  activeCount,
  onChange,
  onReset,
}: PacketFiltersProps) {
  const update = (patch: Partial<PacketExplorerFilters>) => {
    onChange({ ...filters, ...patch });
  };

  return (
    <div className="packet-filters" aria-label="Packet filters">
      <label className="packet-filter-check">
        <input
          type="checkbox"
          checked={filters.hasClearPayload}
          onChange={(event) => update({ hasClearPayload: event.currentTarget.checked })}
        />
        <span>Clear payload</span>
      </label>

      <label className="packet-filter-check">
        <input
          type="checkbox"
          checked={filters.hasHttpHeaderText}
          onChange={(event) => update({ hasHttpHeaderText: event.currentTarget.checked })}
        />
        <span>HTTP header</span>
      </label>

      <label className="packet-filter-select">
        <span>App protocol</span>
        <select
          value={filters.appProtocol}
          onChange={(event) =>
            update({ appProtocol: event.currentTarget.value as PacketProtocolFilter })
          }
        >
          <option value="all">All</option>
          <option value="http">HTTP</option>
          <option value="websocket">WebSocket</option>
          <option value="other">Other</option>
        </select>
      </label>

      <button
        type="button"
        className="packet-filter-reset"
        disabled={activeCount === 0}
        onClick={onReset}
      >
        Reset
      </button>
    </div>
  );
}
