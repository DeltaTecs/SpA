import type { ProtocolSegment } from "../../api/types";

const BAR_COLORS: Record<string, string> = {
  UDP: "#f2994a",
  TCP: "#27ae60",
  TLS: "#9b51e0",
  QUIC: "#2d9cdb",
  DTLS: "#bb6bd9",
  DNS: "#56ccf2",
  HTTP: "#2f80ed",
  WebSocket: "#eb5757",
  Other: "#7b8794",
};

export function ProtocolDistribution({ segments }: { segments: ProtocolSegment[] }) {
  const hasData = segments.some((segment) =>
    segment.protocols.some((protocol) => protocol.count > 0),
  );

  if (!hasData) return <div className="chart-empty">No protocol data.</div>;

  return (
    <div className="protocol-segments">
      {segments.map((segment) => (
        <ProtocolSegmentChart key={segment.name} segment={segment} />
      ))}
    </div>
  );
}

function ProtocolSegmentChart({ segment }: { segment: ProtocolSegment }) {
  const max = Math.max(...segment.protocols.map((protocol) => protocol.count), 1);

  return (
    <section className="protocol-segment" aria-label={segment.name}>
      <h3 className="protocol-segment__title">{segment.name}</h3>
      <div className="protocol-segment__bars">
        {segment.protocols.map((protocol) => (
          <div className="protocol-segment__row" key={protocol.name}>
            <span className="protocol-segment__name">{protocol.name}</span>
            <span className="protocol-segment__track">
              <span
                className="protocol-segment__bar"
                style={{
                  width: `${(protocol.count / max) * 100}%`,
                  backgroundColor: BAR_COLORS[protocol.name] ?? BAR_COLORS.Other,
                }}
              />
            </span>
            <span className="protocol-segment__count">
              {protocol.count.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}
