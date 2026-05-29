// Stable mapping from an association key to readable row colors, so packets
// sharing the same flow/HTTP stream key get the same tint in the list.

interface AssociationColors {
  background: string;
  accent: string;
}

interface ColorParts {
  hue: number;
  saturation: number;
  backgroundLightness: number;
  accentLightness: number;
}

const TRANSPARENT_COLORS: AssociationColors = {
  background: "transparent",
  accent: "transparent",
};

// Non-cryptographic 128-bit hash. Four independent channels keep color
// collisions far less likely than reducing every key to a 360-step hue.
function hash128(value: string): [number, number, number, number] {
  let h1 = 1779033703;
  let h2 = 3144134277;
  let h3 = 1013904242;
  let h4 = 2773480762;

  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ code, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ code, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ code, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ code, 2716044179);
  }

  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);

  h1 = (h1 ^ h2 ^ h3 ^ h4) >>> 0;
  h2 = (h2 ^ h1) >>> 0;
  h3 = (h3 ^ h1) >>> 0;
  h4 = (h4 ^ h1) >>> 0;

  return [h1, h2, h3, h4];
}

function unitInterval(value: number): number {
  return value / 0x100000000;
}

function colorPartsForKey(key: string): ColorParts {
  const [hueHash, saturationHash, backgroundHash, accentHash] = hash128(key);

  return {
    hue: unitInterval(hueHash) * 360,
    saturation: 58 + unitInterval(saturationHash) * 24,
    backgroundLightness: 88 + unitInterval(backgroundHash) * 7,
    accentLightness: 44 + unitInterval(accentHash) * 20,
  };
}

function hsl(hue: number, saturation: number, lightness: number): string {
  return `hsl(${hue.toFixed(2)}, ${saturation.toFixed(1)}%, ${lightness.toFixed(1)}%)`;
}

/** Deterministic color pair for an association key. */
export function colorsForKey(key: string | null | undefined): AssociationColors {
  if (!key) return TRANSPARENT_COLORS;

  const { hue, saturation, backgroundLightness, accentLightness } = colorPartsForKey(key);
  return {
    background: hsl(hue, saturation, backgroundLightness),
    accent: hsl(hue, saturation, accentLightness),
  };
}

/** Deterministic light background for a given association key. */
export function colorForKey(key: string | null | undefined): string {
  return colorsForKey(key).background;
}

/** A stronger accent of the same key color, e.g. for a left border. */
export function accentForKey(key: string | null | undefined): string {
  return colorsForKey(key).accent;
}
