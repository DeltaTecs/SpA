import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { DirectionCounts } from "../../api/types";

const COLORS: Record<string, string> = {
  outgoing: "#2f80ed",
  incoming: "#27ae60",
  unknown: "#b0bec5",
};

export function DirectionChart({ data }: { data: DirectionCounts }) {
  const slices = [
    { name: "outgoing", value: data.outgoing },
    { name: "incoming", value: data.incoming },
    { name: "unknown", value: data.unknown },
  ].filter((s) => s.value > 0);

  if (slices.length === 0) return <div className="chart-empty">No direction data.</div>;

  return (
    <ResponsiveContainer width="100%" height={260}>
      <PieChart>
        <Pie data={slices} dataKey="value" nameKey="name" outerRadius={90} label>
          {slices.map((slice) => (
            <Cell key={slice.name} fill={COLORS[slice.name]} />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}
