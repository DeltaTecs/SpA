import { useState } from "react";
import type { ReactNode } from "react";
import { getRecordings, getStats } from "../api/stats";
import type { RecordingInfo, RecordingStats } from "../api/types";
import { DirectionChart } from "../components/dashboard/DirectionChart";
import { EndpointTree } from "../components/dashboard/EndpointTree";
import { EntropyHistogram } from "../components/dashboard/EntropyHistogram";
import { ProtocolDistribution } from "../components/dashboard/ProtocolDistribution";
import { RemoteIpTable } from "../components/dashboard/RemoteIpTable";
import { StatCard } from "../components/dashboard/StatCard";
import { ErrorBanner } from "../components/common/ErrorBanner";
import { Loading } from "../components/common/Loading";
import { useFetch } from "../lib/useFetch";

// The brief asks for the default recording (id 1); a selector keeps it flexible.
const DEFAULT_RECORDING_ID = 1;

export function DashboardPage() {
  const [recordingId, setRecordingId] = useState(DEFAULT_RECORDING_ID);
  const recordings = useFetch<RecordingInfo[]>(() => getRecordings(), []);
  const stats = useFetch<RecordingStats>(() => getStats(recordingId), [recordingId]);

  return (
    <div className="page">
      <header className="page__header">
        <h1>Dashboard</h1>
        <RecordingSelector
          recordings={recordings.data}
          value={recordingId}
          onChange={setRecordingId}
        />
      </header>

      {stats.loading && <Loading label="Loading statistics…" />}
      {stats.error && <ErrorBanner message={stats.error} />}
      {stats.data && <DashboardContent stats={stats.data} />}
    </div>
  );
}

function DashboardContent({ stats }: { stats: RecordingStats }) {
  const directionTotal = stats.direction.incoming + stats.direction.outgoing + stats.direction.unknown;
  return (
    <>
      <div className="stat-row">
        <StatCard label="Packets stored" value={stats.packet_count.toLocaleString()} hint={`recording #${stats.recording_id}`} />
        <StatCard label="Outgoing" value={stats.direction.outgoing.toLocaleString()} hint="local → remote" />
        <StatCard label="Incoming" value={stats.direction.incoming.toLocaleString()} hint="remote → local" />
        <StatCard label="Remote IPs" value={stats.remote_ips.length.toLocaleString()} hint="distinct peers (top 50)" />
      </div>

      <div className="panel-grid">
        <Panel title="Protocol distribution">
          <ProtocolDistribution data={stats.protocol_distribution} />
        </Panel>
        <Panel title={`Direction (${directionTotal.toLocaleString()} packets)`}>
          <DirectionChart data={stats.direction} />
        </Panel>
        <Panel title="Payload entropy distribution">
          <EntropyHistogram data={stats.entropy_histogram} />
        </Panel>
        <Panel title="Top remote IP addresses">
          <RemoteIpTable data={stats.remote_ips} />
        </Panel>
        <Panel title="Remote IP → host → endpoint tree" wide>
          <EndpointTree nodes={stats.endpoint_tree} />
        </Panel>
      </div>
    </>
  );
}

function Panel({ title, children, wide }: { title: string; children: ReactNode; wide?: boolean }) {
  return (
    <section className={`panel${wide ? " panel--wide" : ""}`}>
      <h2 className="panel__title">{title}</h2>
      <div className="panel__body">{children}</div>
    </section>
  );
}

interface RecordingSelectorProps {
  recordings: RecordingInfo[] | null;
  value: number;
  onChange: (id: number) => void;
}

function RecordingSelector({ recordings, value, onChange }: RecordingSelectorProps) {
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
