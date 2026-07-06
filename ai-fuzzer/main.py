"""
AI-powered semantic API fuzzer — CLI entrypoint.

Pipeline:  load spec -> extract targets -> (per unique param) LLM payloads
           -> inject each payload into an otherwise-valid request -> judge
           -> write JSON + HTML report + non-zero exit on FAIL.

Designed to need zero per-API configuration: point it at an OpenAPI URL and go.
The only optional input is --overrides for real business ids so deep endpoints
don't just bounce off 404s.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from spec_parser import SpecParser
from payload_generator import PayloadGenerator
from runner import Runner, finding_to_dict
from report import write_html_report, write_markdown_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AI semantic API fuzzer")
    p.add_argument("--spec", required=True,
                   help="OpenAPI URL or local file path (JSON or YAML, either way)")
    p.add_argument("--base-url", default=None, help="Target base URL (defaults to spec servers[0])")
    p.add_argument("--auth", default=os.environ.get("TARGET_AUTH", ""),
                   help="Value for Authorization header, e.g. 'Bearer xxx'")
    p.add_argument("--header", action="append", default=[],
                   help="Extra header 'Key: Value' (repeatable)")
    p.add_argument("--overrides", default=None,
                   help="JSON file mapping param name -> valid value (real ids, etc.)")
    p.add_argument("--out", default="/data/reports", help="Report output dir")
    p.add_argument("--offline", action="store_true",
                   help="Skip the LLM, use built-in deterministic payloads")
    p.add_argument("--max-ops", type=int, default=0,
                   help="Limit number of operations (0 = all) for smoke runs")
    p.add_argument("--fail-on", choices=["fail", "warn", "never"], default="fail",
                   help="Exit non-zero when findings reach this severity")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    spec_headers = {}
    if args.auth:
        spec_headers["Authorization"] = args.auth

    print(f"[*] loading spec: {args.spec}")
    parser = SpecParser.load(args.spec, headers=spec_headers)
    base_url = args.base_url or parser.base_url()
    if not base_url:
        print("[!] no base URL — pass --base-url or add servers[] to the spec", file=sys.stderr)
        return 2
    print(f"[*] target base URL: {base_url}")

    targets = parser.targets()
    if not targets:
        print("[!] no injectable parameters found in spec", file=sys.stderr)
        return 2

    # optionally trim to N operations for a quick smoke run
    if args.max_ops > 0:
        keep_ops = []
        seen = set()
        for t in targets:
            if t.operation_id not in seen:
                if len(seen) >= args.max_ops:
                    continue
                seen.add(t.operation_id)
            keep_ops.append(t)
        targets = keep_ops

    op_count = len({t.operation_id for t in targets})
    print(f"[*] {len(targets)} injectable params across {op_count} operations")

    headers = {}
    if args.auth:
        headers["Authorization"] = args.auth
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    overrides = {}
    if args.overrides:
        overrides = json.loads(Path(args.overrides).read_text())

    gen = PayloadGenerator(cache_dir=os.environ.get("FUZZ_CACHE", "/data/cache"))
    runner = Runner(base_url, headers=headers, overrides=overrides)

    findings = []
    try:
        for i, target in enumerate(targets, 1):
            payloads = gen.generate(target, offline=args.offline)
            print(f"  [{i}/{len(targets)}] {target.method.upper()} {target.path} "
                  f"[{target.location}:{target.name}] -> {len(payloads)} payloads")
            for pobj in payloads:
                if not isinstance(pobj, dict):
                    pobj = {"value": pobj, "category": "unknown"}
                finding = runner.run_one(target, targets, pobj)
                findings.append(finding)
    finally:
        runner.close()

    # ---- report -----------------------------------------------------------
    counts = Counter(f.verdict for f in findings)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    json_path = out_dir / f"ai-fuzz-{stamp}.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "spec": args.spec,
        "summary": dict(counts),
        "total": len(findings),
        "findings": [finding_to_dict(f) for f in findings],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2))

    html_path = out_dir / f"ai-fuzz-{stamp}.html"
    write_html_report(html_path, payload)

    md_path = out_dir / f"ai-fuzz-{stamp}.md"
    write_markdown_report(md_path, payload)

    print("\n===== AI FUZZ SUMMARY =====")
    print(f"  PASS: {counts.get('PASS', 0)}")
    print(f"  WARN: {counts.get('WARN', 0)}")
    print(f"  FAIL: {counts.get('FAIL', 0)}")
    print(f"  report: {json_path}")
    print(f"  report: {html_path}")
    print(f"  report: {md_path}")

    # ---- exit code --------------------------------------------------------
    if args.fail_on == "never":
        return 0
    if args.fail_on == "warn" and (counts.get("FAIL") or counts.get("WARN")):
        return 1
    if args.fail_on == "fail" and counts.get("FAIL"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
