"""
ExfilWatch — observability: Prometheus-format metrics + structured JSON logs.

Zero extra dependencies: the /metrics output is standard Prometheus text
exposition format, so any Prometheus/Grafana/Datadog agent can scrape it.
Labels are bounded (action names, route *templates*, status codes) so
cardinality can't be blown up by an attacker.
"""

import json
import logging
import threading
import time

_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._scans: dict[str, int] = {}
        self._http: dict[tuple[str, str, int], int] = {}
        self._hist_counts = [0] * len(_BUCKETS)
        self._hist_sum = 0.0
        self._hist_n = 0
        self._rate_limited = 0
        self.started = time.time()

    def observe_scan(self, action: str, seconds: float):
        with self._lock:
            self._scans[action] = self._scans.get(action, 0) + 1
            self._hist_sum += seconds
            self._hist_n += 1
            for i, b in enumerate(_BUCKETS):
                if seconds <= b:
                    self._hist_counts[i] += 1

    def observe_http(self, method: str, path: str, status: int):
        with self._lock:
            k = (method, path, status)
            self._http[k] = self._http.get(k, 0) + 1

    def observe_rate_limited(self):
        with self._lock:
            self._rate_limited += 1

    def render(self) -> str:
        with self._lock:
            out = ["# HELP exfilwatch_scans_total Scans by policy action.",
                   "# TYPE exfilwatch_scans_total counter"]
            for action, n in sorted(self._scans.items()):
                out.append(f'exfilwatch_scans_total{{action="{action}"}} {n}')
            out += ["# HELP exfilwatch_scan_seconds Detection pipeline latency.",
                    "# TYPE exfilwatch_scan_seconds histogram"]
            for b, c in zip(_BUCKETS, self._hist_counts):
                out.append(f'exfilwatch_scan_seconds_bucket{{le="{b}"}} {c}')
            out.append(f'exfilwatch_scan_seconds_bucket{{le="+Inf"}} {self._hist_n}')
            out.append(f"exfilwatch_scan_seconds_sum {self._hist_sum:.6f}")
            out.append(f"exfilwatch_scan_seconds_count {self._hist_n}")
            out += ["# HELP exfilwatch_http_requests_total HTTP requests.",
                    "# TYPE exfilwatch_http_requests_total counter"]
            for (m, p, s), n in sorted(self._http.items()):
                out.append(f'exfilwatch_http_requests_total{{method="{m}",path="{p}",status="{s}"}} {n}')
            out += ["# HELP exfilwatch_rate_limited_total Requests rejected with 429.",
                    "# TYPE exfilwatch_rate_limited_total counter",
                    f"exfilwatch_rate_limited_total {self._rate_limited}",
                    "# TYPE exfilwatch_uptime_seconds gauge",
                    f"exfilwatch_uptime_seconds {time.time() - self.started:.0f}"]
            return "\n".join(out) + "\n"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {"ts": round(record.created, 3), "level": record.levelname, "msg": record.getMessage()}
        extra = getattr(record, "fields", None)
        if extra:
            doc.update(extra)
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=True)


def configure_logging() -> logging.Logger:
    log = logging.getLogger("exfilwatch")
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(JsonFormatter())
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log


metrics = Metrics()
