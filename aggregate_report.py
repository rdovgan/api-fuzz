#!/usr/bin/env python3
"""
Combine schemathesis (JUnit XML), ZAP (JSON), and ai-fuzzer (JSON) output from
one run.sh invocation into a single Markdown summary — one report to read
regardless of which/how many layers ran.

Stdlib only, so it needs no venv: run.sh (and run-local.sh) call it directly
with `python3`.
"""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _first_line(text: str) -> str:
    """Schemathesis failure text starts with a 'Test Case ID:' preamble line;
    the actual reason is the next non-blank '- ...' bullet."""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("test case id") or line[0].isdigit():
            continue
        return line.lstrip("-").strip()
    return "(no detail)"


def render_schemathesis(paths: list[str]) -> tuple[str, bool]:
    if not paths:
        return "_not run_\n", False
    tests = failures = errors = 0
    fail_rows = []
    for p in paths:
        try:
            root = ET.parse(p).getroot()
        except (ET.ParseError, OSError) as exc:
            fail_rows.append(f"| - | - | could not parse {p}: {exc} |")
            continue
        for ts in root.findall("testsuite") or [root]:
            tests += int(ts.attrib.get("tests", 0))
            failures += int(ts.attrib.get("failures", 0))
            errors += int(ts.attrib.get("errors", 0))
            for tc in list(ts):
                probs = tc.findall("failure") + tc.findall("error")
                for prob in probs:
                    fail_rows.append(
                        f"| `{_md_escape(tc.attrib.get('name', '?'))}` "
                        f"| {_md_escape(_first_line(prob.text or ''))} |"
                    )
    lines = [f"- **Operations tested:** {tests}  ·  **failures:** {failures}  ·  **errors:** {errors}", ""]
    if fail_rows:
        lines += ["| Endpoint | Issue |", "|---|---|"] + fail_rows
    else:
        lines.append("No failures." if tests else "No results found.")
    return "\n".join(lines) + "\n", (failures + errors) > 0


def render_zap(path: str | None) -> tuple[str, bool]:
    if not path or not Path(path).exists():
        return "_not run_\n", False
    try:
        data = json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return f"could not parse {path}: {exc}\n", False

    by_risk: dict[str, list[dict]] = {}
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = (alert.get("riskdesc") or "Unknown").split(" ")[0]
            by_risk.setdefault(risk, []).append(alert)

    order = ["High", "Medium", "Low", "Informational", "Unknown"]
    lines = []
    total = sum(len(v) for v in by_risk.values())
    lines.append(f"- **Alerts:** {total}")
    for risk in order:
        alerts = by_risk.get(risk)
        if not alerts:
            continue
        lines.append(f"\n**{risk}** ({len(alerts)})")
        lines.append("| Alert | Instances |")
        lines.append("|---|---|")
        for a in alerts:
            lines.append(f"| {_md_escape(a.get('name', '?'))} | {len(a.get('instances', []))} |")
    if total == 0:
        lines.append("No alerts.")
    has_risk = bool(by_risk.get("High")) or bool(by_risk.get("Medium"))
    return "\n".join(lines) + "\n", has_risk


def render_ai(path: str | None) -> tuple[str, bool]:
    if not path or not Path(path).exists():
        return "_not run_\n", False
    try:
        data = json.loads(Path(path).read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return f"could not parse {path}: {exc}\n", False

    s = data.get("summary", {})
    lines = [
        f"- **Checks:** {data.get('total', 0)}  ·  "
        f"PASS {s.get('PASS', 0)} · WARN {s.get('WARN', 0)} · FAIL {s.get('FAIL', 0)}",
        "",
    ]
    rows = [f for f in data.get("findings", []) if f["verdict"] != "PASS"]
    if rows:
        lines += ["| Verdict | Endpoint | Category | Reason |", "|---|---|---|---|"]
        for f in rows:
            lines.append(
                f"| {f['verdict']} | `{f['method'].upper()} {_md_escape(f['path'])}` "
                f"| {_md_escape(f['category'])} | {_md_escape(f['reason'])} |"
            )
    else:
        lines.append("No WARN/FAIL findings.")
    return "\n".join(lines) + "\n", s.get("FAIL", 0) > 0


def main() -> int:
    p = argparse.ArgumentParser(description="Aggregate all layers into one Markdown report")
    p.add_argument("--out", required=True)
    p.add_argument("--spec-url", default="")
    p.add_argument("--spec-file", default="")
    p.add_argument("--target-url", default="")
    p.add_argument("--generated-at", default="")
    p.add_argument("--junit", nargs="*", default=[])
    p.add_argument("--zap-json", default="")
    p.add_argument("--ai-json", default="")
    args = p.parse_args()

    sth_md, sth_fail = render_schemathesis(args.junit)
    zap_md, zap_fail = render_zap(args.zap_json or None)
    ai_md, ai_fail = render_ai(args.ai_json or None)
    overall_fail = sth_fail or zap_fail or ai_fail

    meta = []
    if args.target_url:
        meta.append(f"- **Target:** `{args.target_url}`")
    if args.spec_url:
        meta.append(f"- **Spec (source):** `{args.spec_url}`")
    if args.spec_file:
        meta.append(f"- **Spec (fetched copy used for this run):** `{args.spec_file}`")
    if args.generated_at:
        meta.append(f"- **Generated:** {args.generated_at}")

    out = [
        "# API Fuzz — Aggregate Report",
        "",
        *meta,
        "",
        f"## Overall: {'❌ FAIL' if overall_fail else '✅ PASS'}",
        "",
        "## Layer 1 — Schemathesis (types, boundaries, schema conformance)",
        "",
        sth_md,
        "## Layer 2 — OWASP ZAP (active security scan)",
        "",
        zap_md,
        "## Layer 3 — ai-fuzzer (semantic payloads)",
        "",
        ai_md,
    ]
    Path(args.out).write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"[*] aggregate report: {args.out}")
    return 1 if overall_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
