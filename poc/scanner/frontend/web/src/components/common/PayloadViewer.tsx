import { useMemo, useState } from "react";
import type { PacketPayload } from "../../api/types";
import { formatBytes } from "../../lib/format";
import { base64ToBytes, decodeText, hexdump } from "../../lib/hexdump";

interface PayloadViewerProps {
  payload: PacketPayload;
  emptyLabel?: string;
}

export function PayloadViewer({
  payload,
  emptyLabel = "No decrypted application payload.",
}: PayloadViewerProps) {
  const [view, setView] = useState<"hex" | "text">("hex");
  const bytes = useMemo(
    () => base64ToBytes(payload.clear_application_payload),
    [payload.clear_application_payload],
  );

  if (payload.clear_application_payload_length === 0) {
    return <div className="state">{emptyLabel}</div>;
  }

  return (
    <div className="payload">
      <div className="payload__tabs">
        <button
          type="button"
          className={`tab${view === "hex" ? " tab--active" : ""}`}
          onClick={() => setView("hex")}
        >
          Hex
        </button>
        <button
          type="button"
          className={`tab${view === "text" ? " tab--active" : ""}`}
          onClick={() => setView("text")}
        >
          Text
        </button>
        <span className="payload__size">{formatBytes(payload.clear_application_payload_length)}</span>
      </div>
      <pre className="payload__body mono">
        {view === "hex" ? hexdump(bytes) : decodeText(bytes)}
      </pre>
    </div>
  );
}
