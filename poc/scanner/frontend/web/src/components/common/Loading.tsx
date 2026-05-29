export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="state state--loading">{label}</div>;
}
