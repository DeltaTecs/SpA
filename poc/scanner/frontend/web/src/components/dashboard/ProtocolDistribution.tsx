import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { NameCount } from "../../api/types";

// Protocols the brief calls out explicitly get a distinct accent color.
const HIGHLIGHT: Record<string, string> = {
  HTTP: "#2f80ed",
  TLS: "#9b51e0",
  TCP: "#27ae60",
  UDP: "#f2994a",
};
const DEFAULT_COLOR = "#b0bec5";

export function ProtocolDistribution({ data }: { data: NameCount[] }) {
  if (data.length === 0) return <div className="chart-empty">No protocol data.</div>;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eceff1" />
        <XAxis dataKey="name" tick={{ fontSize: 12 }} />
        <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
        <Tooltip />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={HIGHLIGHT[entry.name.toUpperCase()] ?? DEFAULT_COLOR} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
