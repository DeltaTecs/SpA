import type { RemoteIp } from "../../api/types";

export function RemoteIpTable({ data }: { data: RemoteIp[] }) {
  if (data.length === 0) return <div className="chart-empty">No remote IPs.</div>;
  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <div className="ip-table">
      {data.map((row) => (
        <div className="ip-table__row" key={row.ip}>
          <span className="ip-table__ip" title={row.ip}>
            {row.ip}
          </span>
          <span className="ip-table__bar-track">
            <span
              className="ip-table__bar"
              style={{ width: `${(row.count / max) * 100}%` }}
            />
          </span>
          <span className="ip-table__count">{row.count}</span>
        </div>
      ))}
    </div>
  );
}
