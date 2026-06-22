import type { RecordingInfo } from "../../api/types";

interface RecordingSelectorProps {
  recordings: RecordingInfo[] | null;
  value: number;
  onChange: (id: number) => void;
}

/** Recording picker shared by the Dashboard, Explorer and Attack pages. */
export function RecordingSelector({ recordings, value, onChange }: RecordingSelectorProps) {
  const options = recordings ?? [{ recording_id: value, name: null, packet_count: 0 }];
  return (
    <label className="recording-select">
      <span>Recording</span>
      <select value={value} onChange={(e) => onChange(Number(e.target.value))}>
        {options.map((rec) => (
          <option key={rec.recording_id} value={rec.recording_id}>
            #{rec.recording_id}
            {rec.name ? ` – ${rec.name}` : ""} ({rec.packet_count.toLocaleString()})
          </option>
        ))}
      </select>
    </label>
  );
}
