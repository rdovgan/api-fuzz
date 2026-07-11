#!/usr/bin/env bash
#
# Local (non-Docker) runner. Use this instead of run.sh when Docker Desktop's
# VM can't reach TARGET_URL (common with split-tunnel VPNs: the host reaches
# the target fine, but Docker's own network stack doesn't inherit those VPN
# routes). This runs each layer's native CLI directly on your host.
#
# Requirements already satisfied on this machine:
#   - schemathesis  (pip install schemathesis)
#   - ai-fuzzer      (pip install -r ai-fuzzer/requirements.txt)
# zap is NOT wired up here yet — see the message the "zap" layer prints below.
#
# Usage:
#   ./run-local.sh                 # schemathesis + ai
#   ./run-local.sh schemathesis
#   ./run-local.sh ai
#   ./run-local.sh zap             # prints why this isn't automated + how to
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

# Resolve the spec once, so schemathesis and ai-fuzzer both test the exact
# same version instead of each doing its own fetch. SPEC_URL may be either an
# http(s) URL (fetched fresh, bypassing any proxy/CDN cache) or a local JSON/
# YAML OpenAPI file (just used as-is).
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
  echo "[*] using local spec file: ${SPEC_URL}"
  SPEC_FILE="${SPEC_URL}"
fi

# Two-step auth: TARGET_AUTH_HEADER/TARGET_AUTH (e.g. x-api-key) goes on every
# request. If TARGET_LOGIN_PATH is set, log in first to get a JWT and send it
# as a second header (Authorization: Bearer <token>) so business endpoints
# that require both don't just bounce off 401.
BEARER_TOKEN=""
if [[ -n "${TARGET_LOGIN_PATH:-}" && -n "${TARGET_LOGIN_USERNAME:-}" ]]; then
  echo "[*] logging in via ${TARGET_URL}${TARGET_LOGIN_PATH} to obtain bearer token"
  LOGIN_RESPONSE=$(curl -fsS --max-time 15 \
    -H "${TARGET_AUTH_HEADER:-x-api-key}: ${TARGET_AUTH:-}" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TARGET_LOGIN_USERNAME}\",\"password\":\"${TARGET_LOGIN_PASSWORD:-}\"}" \
    "${TARGET_URL}${TARGET_LOGIN_PATH}" 2>/dev/null)
  BEARER_TOKEN=$(python3 -c "
import json, sys
try:
    print(json.loads(sys.argv[1]).get('token', ''))
except Exception:
    pass
" "${LOGIN_RESPONSE:-}" 2>/dev/null)
  if [[ -z "${BEARER_TOKEN}" ]]; then
    echo "[!] login failed or no 'token' field in response — continuing with ${TARGET_AUTH_HEADER:-x-api-key} only" >&2
  else
    echo "[*] obtained bearer token"
  fi
fi

AUTH_ARGS_STH=(-H "${TARGET_AUTH_HEADER:-Authorization}: ${TARGET_AUTH}")
AUTH_ARGS_AI=(--header "${TARGET_AUTH_HEADER:-Authorization}: ${TARGET_AUTH}")
if [[ -n "${BEARER_TOKEN}" ]]; then
  AUTH_ARGS_STH+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
  AUTH_ARGS_AI+=(--auth "Bearer ${BEARER_TOKEN}")
fi

LAYER="${1:-all}"
declare -A RESULTS

run_schemathesis() {
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  schemathesis (native)"
  echo "════════════════════════════════════════════════════════"
  schemathesis run "${SPEC_FILE}" \
    --url "${TARGET_URL}" \
    --checks all \
    --max-examples "${STH_EXAMPLES:-150}" \
    --max-response-time 5 \
    --continue-on-failure \
    "${AUTH_ARGS_STH[@]}" \
    --report junit \
    --report-dir ./reports \
    --suppress-health-check all
  RESULTS[schemathesis]=$?
}

run_ai() {
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  ai-fuzzer (native)"
  echo "════════════════════════════════════════════════════════"
  if [[ -z "${ANTHROPIC_API_KEY:-}" || "${ANTHROPIC_API_KEY}" == *"..."* || "${ANTHROPIC_API_KEY}" == "your-zai-api-key" ]]; then
    echo "!! ANTHROPIC_API_KEY (Z.ai key) looks unset/placeholder in .env — skipping ai layer." >&2
    RESULTS[ai]=2
    return
  fi
  FUZZ_CACHE="./cache" python3 ai-fuzzer/main.py \
    --spec "${SPEC_FILE}" \
    --base-url "${TARGET_URL}" \
    "${AUTH_ARGS_AI[@]}" \
    --out ./reports \
    --fail-on "${AI_FAIL_ON:-fail}"
  RESULTS[ai]=$?
}

run_zap() {
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "  zap"
  echo "════════════════════════════════════════════════════════"
  if command -v zap.sh >/dev/null 2>&1; then
    echo "zap.sh found on PATH, but there is no native driver script yet —" >&2
    echo "only the Docker path (docker-compose.yml, run.sh zap) is wired up." >&2
    echo "Tell your assistant to build the native ZAP driver now that ZAP is installed." >&2
  else
    echo "ZAP is not installed natively on this machine, and the Docker path" >&2
    echo "can't reach ${TARGET_URL} through your VPN (Docker VM networking issue)." >&2
    echo "" >&2
    echo "To run ZAP locally: brew install --cask zap" >&2
    echo "(then re-run this script — a native driver still needs to be built)." >&2
  fi
  RESULTS[zap]=2
}

case "${LAYER}" in
  schemathesis) run_schemathesis ;;
  ai)           run_ai ;;
  zap)          run_zap ;;
  all)
    run_schemathesis
    run_ai
    ;;
  *)
    echo "unknown layer: ${LAYER} (use: schemathesis | ai | zap | all)" >&2
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
    printf "  %-14s FAIL/SKIP (exit %s)\n" "$k" "$code"
    overall=1
  fi
done
echo ""
echo "  Reports in ./reports/"
ls -1 reports/ 2>/dev/null | sed 's/^/    - /'

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
