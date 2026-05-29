// Stable mapping from an association key to a light background color, so packets
// sharing a key (same conversation / HTTP stream) get the same tint in the list.

function hashString(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
  }
  return hash;
}

/** Deterministic light pastel for a given association key (or transparent). */
export function colorForKey(key: string | null | undefined): string {
  if (!key) return "transparent";
  const hue = hashString(key) % 360;
  // High lightness keeps the foreground text readable across hues.
  return `hsl(${hue}, 65%, 90%)`;
}

/** A slightly stronger accent of the same hue, e.g. for a left border. */
export function accentForKey(key: string | null | undefined): string {
  if (!key) return "transparent";
  const hue = hashString(key) % 360;
  return `hsl(${hue}, 55%, 65%)`;
}
