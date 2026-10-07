#!/usr/bin/env bash
# =============================================================================
# ZTRE Advanced Outsider Attack Simulation - Setup & Common Library
# Implements Phase 0 (Pre-flight) & Phase 1 (Deploy vulnerable-web)
# per doc/ADVANCED_TEST_PLAN.md v1.3.0 / v1.5.0
# =============================================================================
set -uo pipefail

# ---- Path Resolution ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source lib/common.sh if present
if [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/lib/common.sh"
elif [ -f "$REPO_ROOT/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$REPO_ROOT/lib/common.sh"
elif [ -f "lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "lib/common.sh"
fi

# ---- Configuration -----------------------------------------------------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
NODEPORT="${NODEPORT:-30080}"
EXFIL_PORT="${EXFIL_PORT:-9999}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

# Resolve relative EVIDENCE_DIR to REPO_ROOT regardless of CWD
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="${REPO_ROOT}/${EVIDENCE_DIR}" ;;
esac
mkdir -p "$EVIDENCE_DIR"
LOG="${LOG:-$EVIDENCE_DIR/run-$TS.log}"

# ---- Helper Functions --------------------------------------------------------
if ! command -v say >/dev/null 2>&1; then
  say() { echo "$*" | tee -a "$LOG"; }
fi

if ! command -v hdr >/dev/null 2>&1; then
  hdr() { say ""; say "============================================================"; say "$*"; say "============================================================"; }
fi

if ! command -v agent_logs >/dev/null 2>&1; then
  agent_logs() { kubectl logs -n "$AGENT_NS" -l "$AGENT_LABEL" --tail=2000 2>/dev/null || true; }
fi

if ! command -v get_pod >/dev/null 2>&1; then
  get_pod() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true; }
fi

# Portable TCP listener via python3 (bastion has NO nc)
# tcp_catcher <port> <outfile|-> <seconds>: accept ONE connection, copy bytes.
if ! command -v tcp_catcher >/dev/null 2>&1; then
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
if ! command -v reset_agent_and_wait >/dev/null 2>&1; then
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
# PHASE 0 — Pre-flight diagnostics
# =============================================================================
run_preflight() {
  hdr "PHASE 0: Pre-flight diagnostics"

  local tool
  for tool in curl jq kubectl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      say "[FAIL] $tool missing on bastion"
      return 1
    fi
  done
  say "[OK] bastion CLI tools present (curl, jq, kubectl, python3)"

  # Reachability: bastion has NO ping; use ssh batch mode and kubectl
  if ssh -o BatchMode=yes -o ConnectTimeout=3 node2@"$WORKER_IP" true 2>/dev/null; then
    say "[OK] worker node $WORKER_IP reachable (ssh)"
  else
    say "[WARN] ssh to worker $WORKER_IP failed; continuing (kubectl path may still work)"
  fi

  if kubectl get nodes >/dev/null 2>&1; then
    say "[OK] Kubernetes API reachable (kubectl)"
  else
    say "[FAIL] Kubernetes API unreachable via kubectl"
    return 1
  fi

  # Check NodePort 30080 allocation across all namespaces
  local port_in_use occupier
  port_in_use=$(kubectl get svc -A -o jsonpath='{.items[*].spec.ports[*].nodePort}' 2>/dev/null | tr ' ' '\n' | grep -w "$NODEPORT" || true)
  if [ -n "$port_in_use" ]; then
    occupier=$(kubectl get svc -A -o json 2>/dev/null | jq -r ".items[] | select(.spec.ports[]?.nodePort == $NODEPORT) | \"\(.metadata.namespace)/\(.metadata.name)\"" || true)
    if [ -n "$occupier" ] && [ "$occupier" != "$NS/vulnerable-web" ]; then
      say "[FAIL] NodePort $NODEPORT occupied by $occupier"
      return 1
    fi
  fi
  say "[OK] NodePort $NODEPORT available/owned"

  # Clear legacy quarantine labels across target namespace
  kubectl label pod -n "$NS" --all ztre/quarantine- --overwrite >/dev/null 2>&1 || true
  say "[OK] legacy quarantine labels cleared"

  # Verify or deploy vulnerable-app (prerequisite for scenarios 3 & 4)
  local app_pod
  app_pod=$(get_pod vulnerable-app)
  if [ -n "$app_pod" ]; then
    say "[OK] vulnerable-app pod present: $app_pod"
  elif [ -f "${REPO_ROOT}/deploy/workloads/vulnerable-app.yaml" ]; then
    say "[info] deploying vulnerable-app workload..."
    kubectl apply -f "${REPO_ROOT}/deploy/workloads/vulnerable-app.yaml" 2>&1 | tee -a "$LOG" || true
    kubectl rollout status deployment/vulnerable-app -n "$NS" --timeout=60s 2>&1 | tee -a "$LOG" || true
  fi

  return 0
}

# =============================================================================
# PHASE 1 — Deploy vulnerable-web workload
# =============================================================================
run_deploy_web() {
  hdr "PHASE 1: Deploy vulnerable-web workload"

  local manifest="${REPO_ROOT}/deploy/workloads/vulnerable-web.yaml"
  if [ ! -f "$manifest" ]; then
    if [ -f "deploy/workloads/vulnerable-web.yaml" ]; then
      manifest="deploy/workloads/vulnerable-web.yaml"
    else
      say "[FAIL] manifest deploy/workloads/vulnerable-web.yaml not found"
      return 1
    fi
  fi

  say "[info] applying manifest: $manifest"
  kubectl apply -f "$manifest" 2>&1 | tee -a "$LOG"

  say "[info] awaiting deployment/vulnerable-web rollout..."
  kubectl rollout status deployment/vulnerable-web -n "$NS" --timeout=60s 2>&1 | tee -a "$LOG" || true

  WEB_POD=$(get_pod vulnerable-web)
  if [ -z "$WEB_POD" ]; then
    say "[FAIL] vulnerable-web pod not found in namespace $NS"
    return 1
  fi
  say "[info] vulnerable-web pod: $WEB_POD"

  # Wait for readiness condition
  local ready="False"
  local i
  for i in $(seq 1 20); do
    ready=$(kubectl get pod -n "$NS" "$WEB_POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
    if [ "$ready" = "True" ]; then
      break
    fi
    sleep 2
  done
  say "[info] vulnerable-web Ready=$ready"
  if [ "$ready" != "True" ]; then
    say "[FAIL] vulnerable-web failed to become Ready within 40s"
    return 1
  fi

  # Sanity probe: HTTP endpoint responds (NodePort on WORKER_IP)
  local resp
  resp=$(curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=id" 2>/dev/null || true)
  say "[sanity] HTTP response: $resp"

  return 0
}

# ---- Execution Guard ---------------------------------------------------------
main() {
  run_preflight || { say "[FAIL] Phase 0 pre-flight failed"; exit 1; }
  run_deploy_web || { say "[FAIL] Phase 1 deploy vulnerable-web failed"; exit 1; }
  say "[OK] Pre-flight and deployment complete"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
