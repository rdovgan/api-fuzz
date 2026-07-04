"""
Request runner + response oracle.

For each target we build an otherwise-valid request (sensible defaults for the
remaining params, optional user-supplied overrides for real business ids) and
inject one payload at a time. The oracle then classifies the response:

  FAIL  - 5xx, or a DB/stack-trace/interpreter signature leaked in the body,
          or the payload was reflected verbatim into an HTML-ish response,
          or an injection payload came back 2xx (possibly accepted).
  WARN  - suspicious latency spike (possible time-based injection), or 2xx on a
          clearly malformed value.
  PASS  - clean 4xx rejection or safely-handled response.

The oracle is deliberately conservative: it flags things for a human to look at
rather than trying to be a full scanner (ZAP covers the heavy security scan).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, asdict
from typing import Any

import httpx

from spec_parser import InjectionTarget

# signatures that should never appear in a well-behaved response body
_LEAK_SIGNATURES = [
    r"SQL syntax.*MySQL", r"org\.hibernate\.", r"java\.sql\.SQLException",
    r"com\.mysql\.", r"ORA-\d{5}", r"PostgreSQL.*ERROR", r"SQLServer",
    r"MongoError", r"you have an error in your sql syntax",
    r"at java\.[\w.$]+\(", r"Exception in thread", r"Caused by:",
    r"org\.springframework\.[\w.$]+Exception", r"java\.lang\.[\w.$]+Exception",
    r"NullPointerException", r"stack trace", r"Traceback \(most recent",
    r"/etc/passwd", r"root:.*:0:0:",
]
_LEAK_RE = re.compile("|".join(_LEAK_SIGNATURES), re.IGNORECASE)

# reflection check: xss/ssti payload echoed back unescaped
_REFLECT_MARKERS = ("<script>", "${{", "{{7*7}}", "49")


@dataclass
class Finding:
    verdict: str          # PASS | WARN | FAIL
    operation_id: str
    method: str
    path: str
    location: str
    param: str
    category: str
    payload: Any
    status: int | None
    latency_ms: float
    reason: str


# ----------------------------------------------------------------------------
# default value generation for the *other* (non-injected) parameters
# ----------------------------------------------------------------------------
def _default_for(t: InjectionTarget, overrides: dict[str, Any]) -> Any:
    if t.name in overrides:
        return overrides[t.name]
    c = t.constraints
    if "enum" in c and c["enum"]:
        return c["enum"][0]
    fmt = (t.schema_format or "")
    if fmt == "date":
        return "2025-01-15"
    if fmt == "date-time":
        return "2025-01-15T12:00:00Z"
    if fmt == "email":
        return "qa.probe@example.com"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if t.schema_type == "integer":
        return int(c.get("minimum", 1))
    if t.schema_type == "number":
        return float(c.get("minimum", 1))
    if t.schema_type == "boolean":
        return True
    if t.schema_type == "array":
        return []
    minlen = int(c.get("minLength", 0))
    return "probe" if minlen <= 5 else "p" * minlen


def _set_dotted(body: dict, dotted: str, value: Any) -> None:
    """Set a value into a nested body by dotted path (arrays use first element)."""
    parts = dotted.replace("[]", "").split(".")
    cur = body
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


class Runner:
    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        overrides: dict[str, Any] | None = None,
        timeout: float = 20.0,
        latency_baseline_ms: float = 1500.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.overrides = overrides or {}
        self.latency_baseline_ms = latency_baseline_ms
        self.client = httpx.Client(timeout=timeout, verify=False, follow_redirects=False)

    # build a full request with everything valid except the injected target
    def _build(self, target: InjectionTarget, all_targets: list[InjectionTarget],
               payload: Any) -> tuple[str, dict, dict, dict, Any]:
        siblings = [t for t in all_targets
                    if t.operation_id == target.operation_id and t is not target]

        path = target.path
        query: dict[str, Any] = {}
        hdrs = dict(self.headers)
        body: dict[str, Any] = {}

        def place(t: InjectionTarget, val: Any):
            if t.location == "path":
                # substitute into the URL path template
                nonlocal path
                path = path.replace("{%s}" % t.name, str(val))
            elif t.location == "query":
                query[t.name] = val
            elif t.location == "header":
                hdrs[t.name] = str(val)
            elif t.location == "body":
                _set_dotted(body, t.name, val)

        for s in siblings:
            if s.required or s.location == "path":
                place(s, _default_for(s, self.overrides))
        place(target, payload)

        url = self.base_url + path
        return url, query, hdrs, (body or None), None

    def run_one(self, target: InjectionTarget, all_targets: list[InjectionTarget],
                payload_obj: dict[str, Any]) -> Finding:
        payload = payload_obj.get("value")
        category = payload_obj.get("category", "unknown")
        url, query, hdrs, body, _ = self._build(target, all_targets, payload)

        t0 = time.perf_counter()
        status: int | None = None
        text = ""
        try:
            resp = self.client.request(
                target.method.upper(), url,
                params=query or None,
                json=body if target.method != "get" else None,
                headers=hdrs,
            )
            status = resp.status_code
            text = resp.text[:20000]
        except httpx.TimeoutException:
            latency = (time.perf_counter() - t0) * 1000
            return Finding("WARN", target.operation_id, target.method, target.path,
                           target.location, target.name, category, payload, None,
                           latency, "request timed out (possible time-based injection / DoS)")
        except Exception as exc:  # noqa: BLE001
            latency = (time.perf_counter() - t0) * 1000
            return Finding("WARN", target.operation_id, target.method, target.path,
                           target.location, target.name, category, payload, None,
                           latency, f"transport error: {exc}")
        latency = (time.perf_counter() - t0) * 1000

        return self._judge(target, category, payload, status, text, latency)

    def _judge(self, target, category, payload, status, text, latency) -> Finding:
        def f(verdict, reason):
            return Finding(verdict, target.operation_id, target.method, target.path,
                           target.location, target.name, category, payload, status,
                           round(latency, 1), reason)

        # 1) server errors are always a fail
        if status is not None and 500 <= status < 600:
            return f("FAIL", f"server returned {status} — unhandled input")

        # 2) leaked db/stack signatures
        m = _LEAK_RE.search(text)
        if m:
            return f("FAIL", f"leaked internal signature in body: {m.group(0)[:60]!r}")

        # 3) reflection of active payloads
        if category in ("xss", "ssti") and isinstance(payload, str):
            if any(mk in text for mk in _REFLECT_MARKERS) and payload[:12] in text:
                return f("FAIL", "active payload reflected unescaped in response")

        # 4) latency spike -> possible time-based injection
        if latency > self.latency_baseline_ms * 4 and category in (
                "sql_injection", "nosql_injection", "command_injection"):
            return f("WARN", f"latency {latency:.0f}ms >> baseline — possible time-based injection")

        # 5) injection/oversize accepted with 2xx: worth a look
        if status is not None and 200 <= status < 300 and category in (
                "sql_injection", "nosql_injection", "command_injection",
                "path_traversal", "oversize", "type_confusion", "format_violation"):
            return f("WARN", f"{category} payload accepted with {status} (verify it was neutralised)")

        # 6) clean rejection
        if status is not None and 400 <= status < 500:
            return f("PASS", f"rejected with {status}")

        return f("PASS", f"handled with {status}")

    def close(self):
        self.client.close()


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    d = asdict(finding)
    # keep payloads json-serialisable and bounded
    if isinstance(d["payload"], str) and len(d["payload"]) > 200:
        d["payload"] = d["payload"][:200] + f"...(+{len(d['payload'])-200} chars)"
    return d
