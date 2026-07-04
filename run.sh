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
# Fetch the spec fresh, once, for every layer to share — bypasses any
# proxy/CDN caching so all three layers test the actual current version, and
# guarantees they all test the *same* version even if the doc changes mid-run.
# ---------------------------------------------------------------------------
SPEC_FILE="reports/spec-${STAMP}.json"
bust_url="${SPEC_URL}$([[ "${SPEC_URL}" == *'?'* ]] && echo '&' || echo '?')_=$(date +%s%N)"
echo "[*] fetching fresh spec: ${SPEC_URL}"
if curl -fsS --max-time 30 \
     -H 'Cache-Control: no-cache, no-store, must-revalidate' -H 'Pragma: no-cache' \
     -H "${TARGET_AUTH_HEADER:-Authorization}: ${TARGET_AUTH:-}" \
     "${bust_url}" -o "${SPEC_FILE}" \
   && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${SPEC_FILE}" 2>/dev/null; then
  echo "[*] spec snapshot: ${SPEC_FILE}"
  export SCHEMATHESIS_SPEC="/reports/$(basename "${SPEC_FILE}")"
  export ZAP_SPEC="/zap/wrk/$(basename "${SPEC_FILE}")"
  export AI_SPEC="/data/reports/$(basename "${SPEC_FILE}")"
else
  echo "[!] could not fetch/parse a fresh spec snapshot — falling back to SPEC_URL directly" >&2
  rm -f "${SPEC_FILE}"
  SPEC_FILE="${SPEC_URL}"
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
# shellcheck disable=SC2086
python3 aggregate_report.py --out "${SUMMARY_MD}" \
  --spec-url "${SPEC_URL}" --spec-file "${SPEC_FILE}" --target-url "${TARGET_URL}" \
  --generated-at "$(date -u +%FT%TZ)" \
  --junit ${JUNIT_FILES} --zap-json "${ZAP_JSON}" --ai-json "${AI_JSON}"
echo "  summary: ${SUMMARY_MD}"

rm -f "${MARKER}"
exit "${overall}"
