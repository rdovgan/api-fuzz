#!/usr/bin/env bash
#
# One-shot runner: builds (if needed) and runs all three test layers against the
# target defined in .env, then prints an aggregate verdict and a link to reports.
#
# Exit code: non-zero if ANY layer reports failures (CI-friendly).
#
# Usage:
#   ./run.sh                 # run all three layers
#   ./run.sh schemathesis    # run a single layer
#   ./run.sh zap
#   ./run.sh ai
#
set -uo pipefail
cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  echo "!! .env not found. Copy .env.example -> .env and edit it." >&2
  exit 2
fi

set -a
source .env
set +a

mkdir -p reports cache

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MARKER="reports/.marker-${STAMP}"
touch "${MARKER}"

# ---------------------------------------------------------------------------
# Resolve the spec once, for every layer to share. SPEC_URL may be either an
# http(s) URL (fetched fresh — bypasses any proxy/CDN cache) or a local JSON/
# YAML OpenAPI file (just copied in). Either way every layer tests the exact
# same snapshot, taken once at the start of this run.
# ---------------------------------------------------------------------------
validate_spec() {
  # exit 0 if the file parses as JSON or YAML, whichever it is
  python3 -c "
import sys
text = open(sys.argv[1], encoding='utf-8').read()
try:
    import json
    json.loads(text)
    sys.exit(0)
except Exception:
    pass
try:
    import yaml
    sys.exit(0 if yaml.safe_load(text) is not None else 1)
except Exception:
    sys.exit(1)
" "$1" 2>/dev/null
}

if [[ "${SPEC_URL}" == http://* || "${SPEC_URL}" == https://* ]]; then
  SPEC_FILE="reports/spec-${STAMP}.json"
  bust_url="${SPEC_URL}$([[ "${SPEC_URL}" == *'?'* ]] && echo '&' || echo '?')_=$(date +%s%N)"
  echo "[*] fetching fresh spec: ${SPEC_URL}"
  if curl -fsS --max-time 30 \
       -H 'Cache-Control: no-cache, no-store, must-revalidate' -H 'Pragma: no-cache' \
       -H "${TARGET_AUTH_HEADER:-Authorization}: ${TARGET_AUTH:-}" \
       "${bust_url}" -o "${SPEC_FILE}" \
     && validate_spec "${SPEC_FILE}"; then
    echo "[*] spec snapshot: ${SPEC_FILE}"
    export SCHEMATHESIS_SPEC="/reports/$(basename "${SPEC_FILE}")"
    export ZAP_SPEC="/zap/wrk/$(basename "${SPEC_FILE}")"
    export AI_SPEC="/data/reports/$(basename "${SPEC_FILE}")"
  else
    echo "[!] could not fetch/parse a fresh spec snapshot — falling back to SPEC_URL directly" >&2
    rm -f "${SPEC_FILE}"
    SPEC_FILE="${SPEC_URL}"
  fi
else
  # local OpenAPI file (json or yaml) instead of a URL
  if [[ ! -f "${SPEC_URL}" ]]; then
    echo "!! SPEC_URL is neither an http(s) URL nor an existing local file: ${SPEC_URL}" >&2
    exit 2
  fi
  ext="${SPEC_URL##*.}"
  case "${ext,,}" in
    yaml|yml) SPEC_FILE="reports/spec-${STAMP}.${ext,,}" ;;
    *)        SPEC_FILE="reports/spec-${STAMP}.json" ;;
  esac
  cp "${SPEC_URL}" "${SPEC_FILE}"
  echo "[*] using local spec file: ${SPEC_URL} -> ${SPEC_FILE}"
  export SCHEMATHESIS_SPEC="/reports/$(basename "${SPEC_FILE}")"
  export ZAP_SPEC="/zap/wrk/$(basename "${SPEC_FILE}")"
  export AI_SPEC="/data/reports/$(basename "${SPEC_FILE}")"
fi

LAYER="${1:-all}"
declare -A RESULTS

run_layer () {
  local name="$1"
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  Running layer: ${name}"
  echo "════════════════════════════════════════════════════════"
  docker compose --profile "${name}" up --build --abort-on-container-exit \
      --exit-code-from "$(compose_service "${name}")"
  RESULTS[$name]=$?
  docker compose --profile "${name}" down --remove-orphans >/dev/null 2>&1
}

compose_service () {
  case "$1" in
    schemathesis) echo "schemathesis" ;;
    zap)          echo "zap" ;;
    ai)           echo "ai-fuzzer" ;;
  esac
}

case "${LAYER}" in
  schemathesis|zap|ai) run_layer "${LAYER}" ;;
  all)
    run_layer schemathesis
    run_layer zap
    run_layer ai
    ;;
  *)
    echo "unknown layer: ${LAYER} (use: schemathesis | zap | ai | all)" >&2
    exit 2
    ;;
esac

echo ""
echo "════════════════════════════════════════════════════════"
echo "  AGGREGATE RESULT"
echo "════════════════════════════════════════════════════════"
overall=0
for k in "${!RESULTS[@]}"; do
  code="${RESULTS[$k]}"
  if [[ "$code" -eq 0 ]]; then
    printf "  %-14s PASS\n" "$k"
  else
    printf "  %-14s FAIL (exit %s)\n" "$k" "$code"
    overall=1
  fi
done
echo ""
echo "  Reports in ./reports/"
ls -1 reports/ 2>/dev/null | sed 's/^/    - /'

# ---------------------------------------------------------------------------
# One combined Markdown report across whichever layer(s) ran this time.
# ---------------------------------------------------------------------------
JUNIT_FILES=$(find reports -name 'junit-*.xml' -newer "${MARKER}" 2>/dev/null)
ZAP_JSON=$(find reports -name 'zap-report.json' -newer "${MARKER}" 2>/dev/null | head -1)
AI_JSON=$(find reports -name 'ai-fuzz-*.json' -newer "${MARKER}" 2>/dev/null | head -1)
SUMMARY_MD="reports/summary-${STAMP}.md"
FINDINGS_MD="reports/findings-${STAMP}.md"
# shellcheck disable=SC2086
python3 aggregate_report.py --out "${SUMMARY_MD}" --findings-out "${FINDINGS_MD}" \
  --spec-url "${SPEC_URL}" --spec-file "${SPEC_FILE}" --target-url "${TARGET_URL}" \
  --generated-at "$(date -u +%FT%TZ)" \
  --junit ${JUNIT_FILES} --zap-json "${ZAP_JSON}" --ai-json "${AI_JSON}"
echo "  summary: ${SUMMARY_MD}"
echo "  detailed findings: ${FINDINGS_MD}"

rm -f "${MARKER}"
exit "${overall}"
