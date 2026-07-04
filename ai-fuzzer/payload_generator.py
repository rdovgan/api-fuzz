"""
Context-aware payload generation via the Anthropic API.

For each unique parameter *signature* (not each endpoint) we ask Claude to
produce a set of attack payloads tailored to the field's semantics: SQLi/NoSQLi
through an email field, date-overflow/shift through a date field, IDOR-ish
values through an id field, path traversal through a path/filename field, etc.

Results are cached on disk keyed by signature so repeated runs and repeated
parameters across endpoints don't re-hit the API.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from typing import Any

import anthropic

from spec_parser import InjectionTarget

MODEL = os.environ.get("FUZZ_MODEL", "claude-sonnet-4-5")
MAX_PAYLOADS = int(os.environ.get("FUZZ_MAX_PAYLOADS_PER_PARAM", "12"))

_SYSTEM = """You are a security test-data generator for API fuzzing against a \
system the caller is authorized to test. Given one API parameter, output a JSON \
array of raw attack/edge payload VALUES for that single parameter. Each item:
  {"value": <the raw value to send>, "category": <string>, "expect": <what a \
correctly-hardened API should do, e.g. "reject 400" or "sanitize/escape">}

Categories to cover WHEN RELEVANT to the field semantics (skip ones that make \
no sense for the type):
  sql_injection, nosql_injection, command_injection, path_traversal, xss,
  ssti, xxe, ldap_injection, header_injection, oversize, type_confusion,
  boundary, unicode_edgecase, format_violation, null_or_empty

Rules:
- Tailor payloads to the field meaning inferred from its name/description/format.
  e.g. a "date"/"checkIn" field -> date-shift, overflow, non-ISO, 0000-00-00,
  99999-12-31, leap edge cases; an "email" field -> SQLi/XSS smuggled via the
  local part; an "*id"/"*Id" field -> traversal, negative, huge, other-tenant
  shaped ids; a "path"/"file"/"url" field -> traversal, SSRF-shaped, file://.
- "boundary"/"oversize" must respect declared constraints (minLength, maxLength,
  minimum, maximum, pattern) and deliberately violate them by one and by a lot.
- Return ONLY the JSON array. No prose, no markdown, no backticks.
- Keep it to at most %d items, most-likely-to-break first.""" % MAX_PAYLOADS


class PayloadGenerator:
    def __init__(self, cache_dir: str = "/data/cache", api_key: str | None = None):
        self.client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, sig: str) -> Path:
        h = hashlib.sha256(sig.encode()).hexdigest()[:20]
        return self.cache_dir / f"{h}.json"

    def _fallback(self, t: InjectionTarget) -> list[dict[str, Any]]:
        """Deterministic payloads used if the API is unavailable, so the tool
        still does something useful offline."""
        base = [
            {"value": "' OR '1'='1", "category": "sql_injection", "expect": "reject 400"},
            {"value": "\"><script>alert(1)</script>", "category": "xss", "expect": "sanitize"},
            {"value": "../../../../etc/passwd", "category": "path_traversal", "expect": "reject 400"},
            {"value": "${{7*7}}", "category": "ssti", "expect": "no eval"},
            {"value": "A" * 20000, "category": "oversize", "expect": "reject 400"},
            {"value": None, "category": "null_or_empty", "expect": "reject if required"},
        ]
        if t.schema_type in ("integer", "number"):
            base += [
                {"value": -2147483649, "category": "boundary", "expect": "reject/clamp"},
                {"value": "not_a_number", "category": "type_confusion", "expect": "reject 400"},
            ]
        if (t.schema_format or "").startswith("date"):
            base += [
                {"value": "0000-00-00", "category": "format_violation", "expect": "reject 400"},
                {"value": "99999-12-31", "category": "boundary", "expect": "reject 400"},
            ]
        return base[:MAX_PAYLOADS]

    def generate(self, t: InjectionTarget, *, offline: bool = False) -> list[dict[str, Any]]:
        sig = t.signature()
        cache = self._cache_path(sig)
        if cache.exists():
            try:
                return json.loads(cache.read_text())
            except json.JSONDecodeError:
                pass

        if offline:
            payloads = self._fallback(t)
            cache.write_text(json.dumps(payloads, ensure_ascii=False, indent=2))
            return payloads

        user_msg = json.dumps({
            "name": t.name,
            "location": t.location,
            "type": t.schema_type,
            "format": t.schema_format,
            "description": t.description,
            "constraints": t.constraints,
            "path": t.path,
            "method": t.method,
        }, ensure_ascii=False)

        try:
            resp = self.client.messages.create(
                model=MODEL,
                max_tokens=2000,
                system=_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
            )
            text = "".join(b.text for b in resp.content if b.type == "text").strip()
            text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            payloads = json.loads(text)
            if not isinstance(payloads, list):
                raise ValueError("expected a JSON array")
        except Exception as exc:  # noqa: BLE001 - degrade gracefully
            print(f"  [warn] LLM generation failed for {t.name}: {exc}; using fallback")
            payloads = self._fallback(t)

        cache.write_text(json.dumps(payloads, ensure_ascii=False, indent=2))
        return payloads
