import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { EntropyBucket } from "../../api/types";

export function EntropyHistogram({ data }: { data: EntropyBucket[] }) {
  const total = data.reduce((sum, b) => sum + b.count, 0);
  if (total === 0) return <div className="chart-empty">No entropy data.</div>;

  const rows = data.map((b) => ({
    label: b.range_start.toFixed(1),
    count: b.count,
    range: `${b.range_start.toFixed(2)} – ${b.range_end.toFixed(2)} bits/byte`,
  }));

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={rows} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eceff1" />
        <XAxis dataKey="label" tick={{ fontSize: 11 }} interval={0} />
        <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
        <Tooltip
          formatter={(value: number) => [`${value} packets`, "count"]}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.range ?? ""}
        />
        <Bar dataKey="count" fill="#9b51e0" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
