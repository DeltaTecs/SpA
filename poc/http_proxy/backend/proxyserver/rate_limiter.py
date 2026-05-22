"""Token-bucket rate limiter used to throttle forwarded requests."""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Tuple

logger = logging.getLogger(__name__)

# settings_provider() -> (requests_per_second, burst)
SettingsProvider = Callable[[], Tuple[float, int]]


class RateLimiter:
    """Throttles forwarded requests using a classic token bucket.

    The bucket parameters are read live from ``settings_provider`` on every
    :meth:`acquire`, so a configuration change applied through the API takes
    effect immediately without restarting the proxy.

    A request that finds the bucket empty *blocks* until a token is available.
    Throttling the caller (rather than rejecting it) is the desired behaviour
    for a proxy fronting a scanner: it paces the scan instead of failing it.
    """

    def __init__(self, settings_provider: SettingsProvider) -> None:
        self._settings_provider = settings_provider
        self._lock = threading.Lock()
        self._tokens: float | None = None  # filled lazily on first acquire
        self._timestamp = time.monotonic()

    def acquire(self) -> None:
        """Block until a request is permitted, then consume one token."""
        while True:
            with self._lock:
                refill_per_second, burst = self._settings_provider()
                if refill_per_second <= 0:
                    return  # rate limiting disabled

                capacity = float(max(1, burst))

                now = time.monotonic()
                if self._tokens is None:
                    # Start with a full bucket so the configured burst is
                    # available immediately after startup.
                    self._tokens = capacity
                else:
                    elapsed = now - self._timestamp
                    self._tokens = min(capacity, self._tokens + elapsed * refill_per_second)
                self._timestamp = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                wait_seconds = (1.0 - self._tokens) / refill_per_second

            # Sleep outside the lock so other threads can also make progress.
            time.sleep(wait_seconds)
