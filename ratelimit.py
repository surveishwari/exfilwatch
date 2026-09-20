"""
ExfilWatch — token-bucket rate limiter.

A security gateway that anyone can hammer is a DoS vector (and, for the
proxy endpoint, a way to burn the upstream LLM quota). Each key gets a
bucket that refills continuously; expensive calls cost more tokens.

In-process by design: correct for a single instance. Running several
replicas would move the buckets to Redis (same allow() interface).
"""

import threading
import time


class TokenBucketLimiter:
    def __init__(self, rate_per_min: float, burst: float | None = None, clock=time.monotonic):
        self.refill_per_sec = rate_per_min / 60.0
        self.capacity = float(burst if burst is not None else rate_per_min)
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens >= cost:
                self._buckets[key] = (tokens - cost, now)
                allowed, retry = True, 0.0
            else:
                self._buckets[key] = (tokens, now)
                allowed = False
                retry = (cost - tokens) / self.refill_per_sec if self.refill_per_sec > 0 else 60.0
            if len(self._buckets) > 10_000:  # bound memory: drop idle, refilled buckets
                stale = [k for k, (_, ts) in self._buckets.items() if now - ts > 600]
                for k in stale:
                    del self._buckets[k]
            return allowed, retry
