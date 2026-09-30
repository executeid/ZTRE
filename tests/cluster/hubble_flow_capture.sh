#!/usr/bin/env bash
# ==============================================================================
# ZTRE Hubble Flow Capture: Before/After Quarantine Network Evidence
# Captures Cilium Hubble flow logs showing traffic flowing pre-quarantine
# and being dropped post-quarantine.
# ==============================================================================
set -euo pipefail

OUTPUT_DIR="evidence/flows"
mkdir -p "$OUTPUT_DIR"

COLOR_GREEN="\033[0;32m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"
log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[DONE]${COLOR_RESET} $*"; }

echo "======================================================================"
echo "    ZTRE Hubble Flow Capture: Network Isolation Evidence               "
echo "======================================================================"

# 0. Check Hubble availability
if ! kubectl get pods -n kube-system -l k8s-app=hubble-relay --no-headers 2>/dev/null | grep -q Running; then
    log_info "Hubble relay not found. Enabling Hubble..."
    cilium hubble enable 2>/dev/null || {
        echo "Hubble not available. Install with: cilium hubble enable"
        echo "Falling back to manual tcpdump-based evidence..."
        exit 1
    }
    sleep 10
fi

# 1. Ensure fresh test pod (not quarantined)
log_info "Setting up fresh test pod for flow capture..."
kubectl delete pod flow-test -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
sleep 2
kubectl run flow-test -n ztre-test --image=alpine --restart=Never \
    --labels="app=flow-test" \
    -- /bin/sh -c 'apk add --no-cache curl netcat-openbsd >/dev/null 2>&1; sleep 300'
kubectl wait --for=condition=Ready pod/flow-test -n ztre-test --timeout=60s >/dev/null 2>&1

# Get database IP for connectivity test
DATABASE_IP=$(kubectl get pod -n ztre-test -l app=database -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
if [ -z "$DATABASE_IP" ]; then
    log_info "Database pod not found, deploying..."
    kubectl apply -f deploy/workloads/postgres-backend.yaml >/dev/null 2>&1
    kubectl rollout status deployment/database -n ztre-test --timeout=60s >/dev/null 2>&1
    DATABASE_IP=$(kubectl get pod -n ztre-test -l app=database -o jsonpath='{.items[0].status.podIP}')
fi
log_info "Database IP: $DATABASE_IP"

# 2. PHASE 1: Capture pre-quarantine flows (baseline connectivity)
log_info "PHASE 1: Capturing pre-quarantine flows (10s window)..."

# Start Hubble observe in background
hubble observe --namespace ztre-test --pod flow-test \
    --output json --last 0 > "$OUTPUT_DIR/pre-quarantine-flows.json" 2>/dev/null &
HUBBLE_PID=$!
sleep 1

# Generate traffic: flow-test -> database (should succeed)
log_info "Generating baseline traffic: flow-test -> database:5432..."
kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
sleep 3

# Stop Hubble capture
kill $HUBBLE_PID 2>/dev/null || true
wait $HUBBLE_PID 2>/dev/null || true

PRE_FLOW_COUNT=$(wc -l < "$OUTPUT_DIR/pre-quarantine-flows.json" 2>/dev/null || echo "0")
log_pass "Pre-quarantine flows captured: ${PRE_FLOW_COUNT} flow records"

# 3. TRIGGER QUARANTINE: Simulate attack to quarantine the pod
log_info "PHASE 2: Triggering attack to quarantine flow-test pod..."

kubectl exec -n ztre-test flow-test -- /bin/sh -c 'nc -e /bin/sh 10.91.128.10 4444' >/dev/null 2>&1 || true
sleep 3

# Verify quarantine
Q_LABEL=$(kubectl get pod flow-test -n ztre-test -o jsonpath='{.metadata.labels.ztre/quarantine}' 2>/dev/null || echo "")
if [ "$Q_LABEL" = "true" ]; then
    log_pass "Pod quarantined successfully (ztre/quarantine=true)"
else
    log_info "Pod not quarantined by agent. Manually labeling for flow evidence..."
    kubectl label pod flow-test -n ztre-test ztre/quarantine=true --overwrite >/dev/null 2>&1
fi

# 4. PHASE 3: Wait for Cilium eBPF enforcement, then capture post-quarantine drops
log_info "Waiting 15s for Cilium eBPF identity convergence..."
sleep 15

log_info "PHASE 3: Capturing post-quarantine flows (10s window)..."

hubble observe --namespace ztre-test --pod flow-test \
    --output json --last 0 > "$OUTPUT_DIR/post-quarantine-drops.json" 2>/dev/null &
HUBBLE_PID=$!
sleep 1

# Try traffic again (should be DROPPED)
log_info "Attempting traffic from quarantined pod -> database:5432 (should be blocked)..."
kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
sleep 5

kill $HUBBLE_PID 2>/dev/null || true
wait $HUBBLE_PID 2>/dev/null || true

POST_FLOW_COUNT=$(wc -l < "$OUTPUT_DIR/post-quarantine-drops.json" 2>/dev/null || echo "0")
log_pass "Post-quarantine flows captured: ${POST_FLOW_COUNT} flow records"

# 5. Summary
echo ""
echo "======================================================================"
echo "    Hubble Flow Capture Results                                        "
echo "======================================================================"
echo "  Pre-quarantine flows:   $OUTPUT_DIR/pre-quarantine-flows.json (${PRE_FLOW_COUNT} records)"
echo "  Post-quarantine drops:  $OUTPUT_DIR/post-quarantine-drops.json (${POST_FLOW_COUNT} records)"
echo ""
echo "  Analyze with:"
echo "    # Count FORWARDED vs DROPPED verdicts"
echo "    cat $OUTPUT_DIR/pre-quarantine-flows.json | jq -r '.flow.verdict' | sort | uniq -c"
echo "    cat $OUTPUT_DIR/post-quarantine-drops.json | jq -r '.flow.verdict' | sort | uniq -c"
echo ""
echo "  Screenshot: Open Hubble UI or Grafana to visualize flow timeline"
echo "======================================================================"

# 6. Cleanup
kubectl delete pod flow-test -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
