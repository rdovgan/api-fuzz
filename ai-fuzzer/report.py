"""Minimal self-contained HTML report (no external assets)."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

_VERDICT_COLOR = {"PASS": "#1a7f37", "WARN": "#9a6700", "FAIL": "#cf222e"}


def write_html_report(path: Path, data: dict[str, Any]) -> None:
    rows = []
    for f in data["findings"]:
        if f["verdict"] == "PASS":
            continue  # keep the report focused on WARN/FAIL
        color = _VERDICT_COLOR.get(f["verdict"], "#57606a")
        rows.append(
            "<tr>"
            f"<td><b style='color:{color}'>{f['verdict']}</b></td>"
            f"<td><code>{html.escape(f['method'].upper())} {html.escape(f['path'])}</code></td>"
            f"<td>{html.escape(f['location'])}:{html.escape(str(f['param']))}</td>"
            f"<td>{html.escape(str(f['category']))}</td>"
            f"<td><code>{html.escape(json.dumps(f['payload'], ensure_ascii=False))[:160]}</code></td>"
            f"<td>{f['status'] if f['status'] is not None else '-'}</td>"
            f"<td>{f['latency_ms']}</td>"
            f"<td>{html.escape(f['reason'])}</td>"
            "</tr>"
        )
    s = data["summary"]
    body = f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI API Fuzz Report</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1f2328}}
 h1{{margin:0 0 .3rem}} .meta{{color:#57606a;margin-bottom:1rem}}
 .pills span{{display:inline-block;padding:.25rem .7rem;border-radius:1rem;margin-right:.5rem;color:#fff;font-weight:600}}
 table{{border-collapse:collapse;width:100%;margin-top:1rem}}
 th,td{{border:1px solid #d0d7de;padding:.4rem .5rem;text-align:left;vertical-align:top;font-size:13px}}
 th{{background:#f6f8fa}} code{{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px;word-break:break-all}}
</style></head><body>
<h1>AI Semantic API Fuzz Report</h1>
<div class="meta">{html.escape(data['base_url'])} &middot; {html.escape(data['generated_at'])}
 &middot; {data['total']} checks</div>
<div class="pills">
 <span style="background:#1a7f37">PASS {s.get('PASS',0)}</span>
 <span style="background:#9a6700">WARN {s.get('WARN',0)}</span>
 <span style="background:#cf222e">FAIL {s.get('FAIL',0)}</span>
</div>
<p>Showing WARN and FAIL findings only (PASS omitted for signal).</p>
<table>
<tr><th>Verdict</th><th>Endpoint</th><th>Param</th><th>Category</th>
    <th>Payload</th><th>Status</th><th>ms</th><th>Reason</th></tr>
{''.join(rows) if rows else '<tr><td colspan=8>No WARN/FAIL findings 🎉</td></tr>'}
</table></body></html>"""
    path.write_text(body, encoding="utf-8")


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def write_markdown_report(path: Path, data: dict[str, Any]) -> None:
    s = data["summary"]
    lines = [
        "# AI Semantic API Fuzz Report",
        "",
        f"- **Target:** `{data['base_url']}`",
        f"- **Spec:** `{data['spec']}`",
        f"- **Generated:** {data['generated_at']}",
        f"- **Checks run:** {data['total']}",
        "",
        f"| PASS | WARN | FAIL |",
        f"|---|---|---|",
        f"| {s.get('PASS', 0)} | {s.get('WARN', 0)} | {s.get('FAIL', 0)} |",
        "",
        "Showing WARN and FAIL findings only (PASS omitted for signal).",
        "",
    ]
    rows = [f for f in data["findings"] if f["verdict"] != "PASS"]
    if rows:
        lines += [
            "| Verdict | Endpoint | Param | Category | Payload | Status | ms | Reason |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for f in rows:
            payload = _md_escape(json.dumps(f["payload"], ensure_ascii=False))[:160]
            lines.append(
                f"| {f['verdict']} "
                f"| `{f['method'].upper()} {_md_escape(f['path'])}` "
                f"| {_md_escape(f['location'])}:{_md_escape(f['param'])} "
                f"| {_md_escape(f['category'])} "
                f"| `{payload}` "
                f"| {f['status'] if f['status'] is not None else '-'} "
                f"| {f['latency_ms']} "
                f"| {_md_escape(f['reason'])} |"
            )
    else:
        lines.append("No WARN/FAIL findings.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
