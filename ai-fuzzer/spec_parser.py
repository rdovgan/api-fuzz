"""
OpenAPI 3.0 spec parser.

Walks the spec and yields a flat list of "injectable targets": for every
operation, every parameter (query / path / header) and every leaf property of
the JSON request body, with enough context (name, description, type, format,
constraints) for the LLM to generate semantically-aware payloads.

Supports both a URL (e.g. Spring's /v3/api-docs) and a local file, and either
JSON or YAML in both cases (detected from content, not the extension).
"""

from __future__ import annotations

import json
import copy
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx
import yaml


@dataclass
class InjectionTarget:
    """A single place a payload can be injected into a request."""
    operation_id: str
    method: str          # get / post / ...
    path: str            # /reservations/{id}
    location: str        # query | path | header | body
    name: str            # parameter name or dotted body path, e.g. "guest.email"
    schema_type: str     # string | integer | number | boolean | array | object
    schema_format: str | None       # date, email, uuid, int64, ...
    description: str
    required: bool
    constraints: dict[str, Any] = field(default_factory=dict)  # minLength, pattern, min, max...

    def signature(self) -> str:
        """Stable key for caching LLM payloads across runs/endpoints."""
        c = json.dumps(self.constraints, sort_keys=True)
        return f"{self.location}|{self.name}|{self.schema_type}|{self.schema_format}|{c}"


_CONSTRAINT_KEYS = (
    "minLength", "maxLength", "pattern", "enum",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minItems", "maxItems", "multipleOf",
)


class SpecParser:
    def __init__(self, spec: dict[str, Any]):
        self.spec = spec

    # ---- loading -----------------------------------------------------------
    @classmethod
    def load(cls, source: str, *, headers: dict[str, str] | None = None) -> "SpecParser":
        if source.startswith(("http://", "https://")):
            # force a fresh fetch every run: bypass any proxy/CDN/browser cache
            # sitting between us and the spec endpoint so we always fuzz the
            # OpenAPI doc that is actually live right now.
            no_cache_headers = {
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                **(headers or {}),
            }
            bust = f"{'&' if '?' in source else '?'}_={int(time.time() * 1000)}"
            resp = httpx.get(source + bust, headers=no_cache_headers, timeout=30.0,
                              follow_redirects=True)
            resp.raise_for_status()
            text = resp.text
        else:
            with open(source, "r", encoding="utf-8") as fh:
                text = fh.read()
        return cls(cls._parse(text))

    @staticmethod
    def _parse(text: str) -> dict[str, Any]:
        """Parse an OpenAPI document as JSON or YAML — sniffed from content, since
        a spec fetched from a URL may not have a .json/.yaml extension to go by."""
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            return json.loads(text)
        return yaml.safe_load(text)

    def base_url(self) -> str | None:
        servers = self.spec.get("servers") or []
        if servers and isinstance(servers, list):
            return servers[0].get("url")
        return None

    # ---- $ref resolution ---------------------------------------------------
    def _resolve(self, node: Any, _depth: int = 0) -> Any:
        """Resolve local $ref pointers. Guards against runaway recursion."""
        if _depth > 40:
            return {}
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node["$ref"]
                if ref.startswith("#/"):
                    target = self.spec
                    for part in ref[2:].split("/"):
                        part = part.replace("~1", "/").replace("~0", "~")
                        target = target.get(part, {}) if isinstance(target, dict) else {}
                    return self._resolve(copy.deepcopy(target), _depth + 1)
                return {}
            # merge allOf so constraints/properties are visible
            if "allOf" in node:
                merged: dict[str, Any] = {}
                for sub in node["allOf"]:
                    r = self._resolve(sub, _depth + 1)
                    if isinstance(r, dict):
                        for k, v in r.items():
                            if k == "properties":
                                merged.setdefault("properties", {}).update(v)
                            elif k == "required":
                                merged.setdefault("required", []).extend(v)
                            else:
                                merged[k] = v
                rest = {k: v for k, v in node.items() if k != "allOf"}
                merged.update(self._resolve(rest, _depth + 1))
                return merged
            return {k: self._resolve(v, _depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self._resolve(i, _depth + 1) for i in node]
        return node

    @staticmethod
    def _constraints(schema: dict[str, Any]) -> dict[str, Any]:
        return {k: schema[k] for k in _CONSTRAINT_KEYS if k in schema}

    # ---- body walking ------------------------------------------------------
    def _walk_body(
        self, schema: dict[str, Any], prefix: str, required_set: set[str]
    ) -> Iterable[tuple[str, dict[str, Any], bool]]:
        """Yield (dotted_name, leaf_schema, required) for each leaf in a body schema."""
        schema = self._resolve(schema)
        stype = schema.get("type")
        if stype == "object" or "properties" in schema:
            props = schema.get("properties", {})
            req = set(schema.get("required", []))
            for name, sub in props.items():
                dotted = f"{prefix}.{name}" if prefix else name
                yield from self._walk_body(sub, dotted, req)
        elif stype == "array":
            items = schema.get("items", {})
            yield from self._walk_body(items, f"{prefix}[]", required_set)
        else:
            yield prefix, schema, prefix.split(".")[-1].replace("[]", "") in required_set

    # ---- main iteration ----------------------------------------------------
    def targets(self) -> list[InjectionTarget]:
        out: list[InjectionTarget] = []
        paths = self.spec.get("paths", {})
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            shared_params = item.get("parameters", [])
            for method, op in item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                if not isinstance(op, dict):
                    continue
                op_id = op.get("operationId") or f"{method}_{path}"

                # parameters (query / path / header)
                params = list(shared_params) + list(op.get("parameters", []))
                for p in params:
                    p = self._resolve(p)
                    loc = p.get("in")
                    if loc not in ("query", "path", "header"):
                        continue
                    sch = self._resolve(p.get("schema", {}))
                    out.append(InjectionTarget(
                        operation_id=op_id,
                        method=method.lower(),
                        path=path,
                        location=loc,
                        name=p.get("name", ""),
                        schema_type=sch.get("type", "string"),
                        schema_format=sch.get("format"),
                        description=p.get("description", "") or sch.get("description", ""),
                        required=bool(p.get("required", loc == "path")),
                        constraints=self._constraints(sch),
                    ))

                # request body (json only)
                body = self._resolve(op.get("requestBody", {}))
                content = body.get("content", {})
                json_schema = None
                for ct, media in content.items():
                    if "json" in ct:
                        json_schema = self._resolve(media.get("schema", {}))
                        break
                if json_schema:
                    for dotted, leaf, req in self._walk_body(json_schema, "", set()):
                        leaf = self._resolve(leaf)
                        out.append(InjectionTarget(
                            operation_id=op_id,
                            method=method.lower(),
                            path=path,
                            location="body",
                            name=dotted,
                            schema_type=leaf.get("type", "string"),
                            schema_format=leaf.get("format"),
                            description=leaf.get("description", ""),
                            required=req,
                            constraints=self._constraints(leaf),
                        ))
        return out
