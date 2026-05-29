// Helpers to render a base64 payload as a hexdump or decoded text preview.

export function base64ToBytes(b64: string | null | undefined): Uint8Array {
  if (!b64) return new Uint8Array(0);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Classic 16-bytes-per-line hexdump, capped at `maxBytes`. */
export function hexdump(bytes: Uint8Array, maxBytes = 4096): string {
  const limit = Math.min(bytes.length, maxBytes);
  const lines: string[] = [];
  for (let offset = 0; offset < limit; offset += 16) {
    const slice = bytes.subarray(offset, Math.min(offset + 16, limit));
    const hex: string[] = [];
    let ascii = "";
    for (let i = 0; i < 16; i++) {
      if (i < slice.length) {
        const b = slice[i];
        hex.push(b.toString(16).padStart(2, "0"));
        ascii += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
      } else {
        hex.push("  ");
      }
      if (i === 7) hex.push("");
    }
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.join(" ")}  |${ascii}|`);
  }
  if (bytes.length > limit) {
    lines.push(`... ${bytes.length - limit} more bytes truncated`);
  }
  return lines.join("\n");
}

/** Best-effort decoded text view (UTF-8), capped at `maxBytes`. */
export function decodeText(bytes: Uint8Array, maxBytes = 8192): string {
  const slice = bytes.subarray(0, Math.min(bytes.length, maxBytes));
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(slice);
  } catch {
    return "";
  }
}
