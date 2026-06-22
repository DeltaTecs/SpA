export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

export function formatTimestamp(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "-";
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return String(ms);
  return date.toISOString().replace("T", " ").replace("Z", "");
}

export function formatEntropy(entropy: number | null | undefined): string {
  if (entropy === null || entropy === undefined) return "-";
  return entropy.toFixed(2);
}

export function directionLabel(fromLocal: boolean | null | undefined): string {
  if (fromLocal === true) return "outgoing";
  if (fromLocal === false) return "incoming";
  return "unknown";
}

export function directionShortLabel(fromLocal: boolean | null | undefined): string {
  if (fromLocal === true) return "out";
  if (fromLocal === false) return "in";
  return "-";
}
