"""Parse raw HTTP header blobs into structured request/response fields.

The ``http_header_information.text_header`` column stores the raw header text as
captured. This helper extracts request ``method``, ``host`` and ``path`` values
from either HTTP/1.x header text (``GET /path HTTP/1.1`` + ``Host:`` header) or
HTTP/2 style pseudo-headers (``:method``, ``:path``, ``:authority``). It also
extracts response status information from HTTP/1.x status lines and HTTP/2
``:status`` pseudo-headers.

All functions are pure and tolerant: anything that cannot be parsed (e.g. a
truncated blob) yields ``None`` fields rather than raising.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

# Methods we treat as a valid HTTP/1.x request line start token.
_HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "TRACE",
    "CONNECT",
}


@dataclass(frozen=True)
class HttpRequestInfo:
    """Structured view of the request/response parts of an HTTP header blob."""

    method: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    status_text: Optional[str] = None
    is_request: bool = False
    is_response: bool = False

    @property
    def is_usable(self) -> bool:
        """True when at least a path was recovered (enough to place in the tree)."""
        return self.path is not None


def _split_lines(text: str) -> List[str]:
    # Normalise CRLF / lone CR, drop trailing empties, keep header order.
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return [line for line in normalized.split("\n")]


def _parse_request_line(line: str) -> Optional[Tuple[str, str]]:
    """Return (method, path) if ``line`` is an HTTP/1.x request line."""
    parts = line.split()
    if (
        len(parts) >= 3
        and parts[0].upper() in _HTTP_METHODS
        and parts[2].upper().startswith("HTTP/")
    ):
        return parts[0].upper(), parts[1]
    return None


def _parse_status_line(line: str) -> Optional[Tuple[int, Optional[str]]]:
    """Return (status_code, reason) if ``line`` is an HTTP/1.x status line."""
    parts = line.split(None, 2)
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        return None
    try:
        status_code = int(parts[1])
    except ValueError:
        return None
    reason = parts[2].strip() if len(parts) >= 3 and parts[2].strip() else None
    return status_code, reason


def _header_value(lines: List[str], name: str) -> Optional[str]:
    """Case-insensitive lookup of the first ``name: value`` header."""
    prefix = name.lower() + ":"
    for line in lines:
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def _pseudo_value(lines: List[str], name: str) -> Optional[str]:
    """Lookup of an HTTP/2 pseudo-header like ``:path`` / ``:authority``."""
    prefix = name.lower()
    for line in lines:
        stripped = line.strip()
        low = stripped.lower()
        if low.startswith(prefix):
            rest = stripped[len(name):].lstrip()
            if rest.startswith(":"):
                rest = rest[1:].strip()
            return rest or None
    return None


def parse_http_header(text: Optional[str]) -> HttpRequestInfo:
    """Parse a raw HTTP header blob into :class:`HttpRequestInfo`.

    Recognises HTTP/1.x request lines plus ``Host`` headers, and HTTP/2
    ``:method`` / ``:path`` / ``:authority`` pseudo-headers. Recognises HTTP/1.x
    response status lines and HTTP/2 ``:status`` pseudo-headers. Unparseable
    input returns an empty result.
    """
    if not text:
        return HttpRequestInfo()

    lines = _split_lines(text)
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return HttpRequestInfo()

    # HTTP/1.x request line.
    request_line = _parse_request_line(non_empty[0])
    if request_line is not None:
        method, path = request_line
        host = _header_value(lines, "Host")
        return HttpRequestInfo(method=method, host=host, path=path, is_request=True)

    # HTTP/1.x response status line.
    status_line = _parse_status_line(non_empty[0])
    if status_line is not None:
        status_code, status_text = status_line
        return HttpRequestInfo(
            status_code=status_code,
            status_text=status_text,
            is_response=True,
        )

    # HTTP/2 pseudo-headers (order-independent).
    method = _pseudo_value(lines, ":method")
    path = _pseudo_value(lines, ":path")
    authority = _pseudo_value(lines, ":authority")
    status = _pseudo_value(lines, ":status")
    if path is not None or method is not None:
        return HttpRequestInfo(
            method=method.upper() if method else None,
            host=authority or _header_value(lines, "Host"),
            path=path,
            is_request=True,
        )
    if status is not None:
        try:
            status_code = int(status)
        except ValueError:
            status_code = None
        return HttpRequestInfo(status_code=status_code, is_response=True)

    return HttpRequestInfo()


def split_path_segments(path: Optional[str]) -> List[str]:
    """Split a request path into non-empty segments, ignoring query/fragment.

    ``"/api/v1/users?x=1"`` -> ``["api", "v1", "users"]``. A bare ``"/"`` (or
    empty) yields ``[]`` so it maps to the host root.
    """
    if not path:
        return []
    # Drop query string and fragment.
    clean = path.split("?", 1)[0].split("#", 1)[0]
    return [seg for seg in clean.split("/") if seg]
