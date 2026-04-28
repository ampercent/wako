#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Antigravity Forensics — Smoke Test Suite
# ═══════════════════════════════════════════════════════════════
# Validates that all critical services are running and responsive.
#
# Usage:
#   ./scripts/smoke_test.sh                    # default localhost
#   ./scripts/smoke_test.sh http://myserver    # custom base URL
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

BASE_URL="${1:-http://localhost:80}"
API_URL="${BASE_URL}/api"
PASS=0
FAIL=0
TOTAL=0

# ── Helpers ──────────────────────────────────────────────────

check() {
    local name="$1"
    local url="$2"
    local method="${3:-GET}"
    local body="${4:-}"
    local expect_code="${5:-200}"
    TOTAL=$((TOTAL + 1))

    if [ "$method" = "POST" ]; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$url" \
            -H "Content-Type: application/json" \
            -d "$body" \
            --connect-timeout 5 --max-time 10 2>/dev/null)
    else
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            "$url" \
            --connect-timeout 5 --max-time 10 2>/dev/null)
    fi

    if [ "$HTTP_CODE" = "$expect_code" ]; then
        echo "  ✓  $name (HTTP $HTTP_CODE)"
        PASS=$((PASS + 1))
    else
        echo "  ✗  $name — expected $expect_code, got $HTTP_CODE"
        FAIL=$((FAIL + 1))
    fi
}

check_json_field() {
    local name="$1"
    local url="$2"
    local field="$3"
    local expected="$4"
    TOTAL=$((TOTAL + 1))

    RESPONSE=$(curl -s "$url" --connect-timeout 5 --max-time 10 2>/dev/null)
    VALUE=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$field',''))" 2>/dev/null)

    if [ "$VALUE" = "$expected" ]; then
        echo "  ✓  $name ($field=$VALUE)"
        PASS=$((PASS + 1))
    else
        echo "  ✗  $name — expected $field=$expected, got $VALUE"
        FAIL=$((FAIL + 1))
    fi
}

# ── Header ───────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ANTIGRAVITY FORENSICS — Smoke Tests"
echo "═══════════════════════════════════════════════════════"
echo "  Target: $BASE_URL"
echo "  Time:   $(date -Iseconds)"
echo "───────────────────────────────────────────────────────"
echo ""

# ── 1. Frontend Reachable ────────────────────────────────────
echo "  [Frontend]"
check "Frontend serves HTML" "$BASE_URL/" "GET" "" "200"
echo ""

# ── 2. Health Check ──────────────────────────────────────────
echo "  [Health]"
check "Health endpoint reachable" "$API_URL/health" "GET" "" "200"
check_json_field "Health status OK" "$API_URL/health" "status" "ok"
check_json_field "DB connected" "$API_URL/health" "db" "connected"
echo ""

# ── 3. Auth ──────────────────────────────────────────────────
echo "  [Authentication]"
check "Login endpoint" "$API_URL/auth/login" "POST" \
    '{"username":"admin","password":"admin"}' "200"
echo ""

# ── 4. Hunt Query ────────────────────────────────────────────
echo "  [Hunting]"
check "Hunt query (valid)" "$API_URL/hunt/query" "POST" \
    "{\"query\":\"process_name == 'powershell.exe' AND severity == 'HIGH'\",\"limit\":10}" "200"

check "Hunt query (empty, rejected)" "$API_URL/hunt/query" "POST" \
    '{"query":""}' "400"

check "Hunt query (too long, rejected)" "$API_URL/hunt/query" "POST" \
    "{\"query\":\"$(python3 -c "print('a'*501)")\"}" "400"
echo ""

# ── 5. Metrics ───────────────────────────────────────────────
echo "  [Metrics]"
check "Hunting metrics" "$API_URL/metrics/hunting" "GET" "" "200"
check "Prometheus metrics" "$API_URL/metrics/prom" "GET" "" "200"
echo ""

# ── 6. Saved Queries ─────────────────────────────────────────
echo "  [Saved Queries]"
check "Get saved queries" "$API_URL/hunt/saved" "GET" "" "200"
echo ""

# ── Summary ──────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
    echo "  ALL PASSED: $PASS/$TOTAL"
else
    echo "  RESULT: $PASS passed, $FAIL failed (of $TOTAL)"
fi
echo "═══════════════════════════════════════════════════════"
echo ""

exit "$FAIL"
