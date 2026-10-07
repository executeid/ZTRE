#!/bin/bash
# =============================================================================
# ZTRE Shared Test Library: lib/common.sh
# Common helpers, logging, Prometheus metrics, and agent interaction.
# =============================================================================
set -uo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd -P)"
REPO_ROOT="$(cd "${LIB_DIR}/.." && pwd -P)"

# ---- Configuration with Environment Overrides --------------------------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
NODEPORT="${NODEPORT:-30080}"
EXFIL_PORT="${EXFIL_PORT:-9999}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
case "$EVIDENCE_DIR" in
  /*) ;;
  *) EVIDENCE_DIR="${REPO_ROOT}/${EVIDENCE_DIR}" ;;
esac

LOG="${LOG:-${EVIDENCE_DIR}/run-${TS}.log}"
PROM_PORT="${PROM_PORT:-9092}"
PROM_PF_PID=""

# ---- Logging Helpers ---------------------------------------------------------
say() {
  local msg="$*"
  if [ -n "${LOG:-}" ]; then
    local dir
    dir="$(dirname "$LOG")"
    [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || true
    echo "$msg" | tee -a "$LOG"
  else
    echo "$msg"
  fi
}

hdr() {
  say ""
  say "============================================================"
  say "$*"
  say "============================================================"
}

pass() {
  local msg="[PASS] $*"
  if [ -t 1 ]; then
    echo -e "\033[0;32m${msg}\033[0m"
    if [ -n "${LOG:-}" ]; then
      local dir
      dir="$(dirname "$LOG")"
      [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || true
      echo "$msg" >> "$LOG"
    fi
  else
    say "$msg"
  fi
}

fail() {
  local msg="[FAIL] $*"
  if [ -t 1 ]; then
    echo -e "\033[0;31m${msg}\033[0m"
    if [ -n "${LOG:-}" ]; then
      local dir
      dir="$(dirname "$LOG")"
      [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || true
      echo "$msg" >> "$LOG"
    fi
  else
    say "$msg"
  fi
}

warn() {
  local msg="[WARN] $*"
  if [ -t 1 ]; then
    echo -e "\033[0;33m${msg}\033[0m"
    if [ -n "${LOG:-}" ]; then
      local dir
      dir="$(dirname "$LOG")"
      [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || true
      echo "$msg" >> "$LOG"
    fi
  else
    say "$msg"
  fi
}

# Compatibility aliases
log_info() { say "[INFO] $*"; }
log_pass() { pass "$*"; }
log_fail() { fail "$*"; }
log_warn() { warn "$*"; }

# ---- CLI Tool Verification ---------------------------------------------------
require_tools() {
  local tools=("$@")
  if [ ${#tools[@]} -eq 0 ]; then
    tools=(curl jq kubectl python3)
  fi
  local missing=0
  for tool in "${tools[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      fail "Missing required tool: $tool"
      missing=$((missing + 1))
    fi
  done
  if [ "$missing" -gt 0 ]; then
    return 1
  fi
  say "[OK] required tools present: ${tools[*]}"
  return 0
}

# ---- Python TCP Catcher ------------------------------------------------------
tcp_catcher() {
  local port="$1"
  local out="${2:--}"
  local secs="${3:-30}"
  python3 - "$port" "$out" "$secs" <<'PY'
import socket, sys, os
port, out, secs = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(5)
s.settimeout(secs)
try:
    conn, _ = s.accept()
    conn.settimeout(secs)
    if out != "-":
        d = os.path.dirname(out)
        if d:
            os.makedirs(d, exist_ok=True)
        f = open(out, "wb")
    else:
        f = sys.stdout.buffer
    try:
        while True:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                break
            if not data:
                break
            f.write(data)
            f.flush()
    finally:
        if out != "-":
            f.close()
        conn.close()
except socket.timeout:
    pass
finally:
    try:
        s.close()
    except Exception:
        pass
PY
}

# ---- Pod and Agent Helpers ---------------------------------------------------
agent_logs() {
  local tail="${1:-2000}"
  kubectl logs -n "$AGENT_NS" -l "$AGENT_LABEL" --tail="$tail" 2>/dev/null
}

agent_since() {
  local since="${1:-}"
  if [ -n "$since" ]; then
    { agent_logs 2000 2>/dev/null || true; } | jq -c -rR --arg s "$since" 'fromjson? | select(.timestamp != null and .timestamp >= $s)' 2>/dev/null || true
  else
    { agent_logs 2000 2>/dev/null || true; } | jq -c -rR 'fromjson? | select(.timestamp != null)' 2>/dev/null || true
  fi
}

get_pod() {
  local app="$1"
  local pod
  pod="$(kubectl get pod -n "$NS" -l "app=${app}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -z "$pod" ]; then
    pod="$(kubectl get pod -n "$NS" "${app}" -o jsonpath='{.metadata.name}' 2>/dev/null || true)"
  fi
  echo "$pod"
}

pod_ip() {
  local target="$1"
  local pod
  pod="$(get_pod "$target")"
  if [ -n "$pod" ]; then
    kubectl get pod -n "$NS" "$pod" -o jsonpath='{.status.podIP}' 2>/dev/null || true
  else
    kubectl get pod -n "$NS" "$target" -o jsonpath='{.status.podIP}' 2>/dev/null || true
  fi
}

is_quarantined() {
  local target="$1"
  local label
  label="$(kubectl get pod -n "$NS" -l "app=${target}" -o jsonpath='{.items[0].metadata.labels.ztre\/quarantine}' 2>/dev/null || true)"
  if [ -z "$label" ]; then
    label="$(kubectl get pod -n "$NS" "${target}" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)"
  fi
  [ "$label" = "true" ]
}

reset_agent_and_wait() {
  local target="$1"
  say "[reset] clearing quarantine label for: $target"
  # If $target looks like a full pod name (contains a 'pod-template-hash'), label
  # it directly. Otherwise treat it as an app label value. NOTE: 'kubectl label
  # -l app=<full-pod-name>' matches ZERO pods but still exits 0, so a naive
  # '||'-chained fallback never fires. Choose explicitly.
  if kubectl get pod -n "$NS" "$target" >/dev/null 2>&1; then
    kubectl label pod -n "$NS" "$target" ztre/quarantine- --overwrite >/dev/null 2>&1 || true
  else
    kubectl label pod -n "$NS" -l "app=$target" ztre/quarantine- --overwrite >/dev/null 2>&1 || true
  fi
  # Verify the label is actually gone; wait up to ~10s for Cilium to converge.
  local lw=10
  while [ "$lw" -gt 0 ]; do
    local cur
    cur=$(kubectl get pods -n "$NS" -l "app=$target" -o jsonpath='{.items[*].metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
    [ -z "$cur" ] && break
    sleep 1; lw=$((lw - 1))
  done

  say "[reset] restarting ztre-agent daemonset (clears sync.Map dedup cache)"
  kubectl rollout restart daemonset -n "$AGENT_NS" ztre-agent >/dev/null 2>&1
  kubectl rollout status daemonset -n "$AGENT_NS" ztre-agent --timeout=40s >/dev/null 2>&1 || true

  local timeout=20
  while [ "$timeout" -gt 0 ]; do
    local agent_pod
    agent_pod="$(kubectl get pod -n "$AGENT_NS" -l "$AGENT_LABEL" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [ -n "$agent_pod" ] && kubectl logs -n "$AGENT_NS" "$agent_pod" --tail=200 2>/dev/null | grep -q "Tetragon gRPC event stream established"; then
      say "[reset] agent gRPC stream confirmed open"
      break
    elif agent_logs 200 | grep -q "Tetragon gRPC event stream established"; then
      say "[reset] agent gRPC stream confirmed open"
      break
    fi
    sleep 1
    timeout=$((timeout - 1))
  done
  sleep 2
}

wait_ready() {
  local target="$1"
  local timeout="${2:-60}"
  local pod=""

  if kubectl get deployment -n "$NS" "$target" >/dev/null 2>&1; then
    kubectl rollout status "deployment/$target" -n "$NS" --timeout="${timeout}s" >/dev/null 2>&1 || true
  fi

  local start_time
  start_time="$(date +%s)"
  while true; do
    pod="$(get_pod "$target")"
    if [ -n "$pod" ]; then
      local r
      r="$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
      if [ "$r" = "True" ]; then
        return 0
      fi
    fi

    local now
    now="$(date +%s)"
    if [ $((now - start_time)) -ge "$timeout" ]; then
      fail "Pod for $target not ready within ${timeout}s"
      return 1
    fi
    sleep 2
  done
}

# ---- Prometheus Metrics via Port-Forward ------------------------------------
prom_start() {
  local port="${1:-$PROM_PORT}"
  PROM_PORT="$port"
  if curl -sf "http://127.0.0.1:${PROM_PORT}/api/v1/query?query=up" >/dev/null 2>&1; then
    return 0
  fi
  pkill -f "port-forward.*prometheus.*${PROM_PORT}" 2>/dev/null || true
  sleep 1
  kubectl port-forward -n monitoring svc/prometheus "${PROM_PORT}:9090" --address 127.0.0.1 \
      >/tmp/prom-pf.log 2>&1 &
  PROM_PF_PID=$!
  sleep 4
}

prom_stop() {
  if [ -n "${PROM_PF_PID:-}" ]; then
    kill "$PROM_PF_PID" 2>/dev/null || true
    PROM_PF_PID=""
  fi
  pkill -f "port-forward.*prometheus.*${PROM_PORT:-9092}" 2>/dev/null || true
}

promval() {
  local expr="$1"
  if ! curl -sf "http://127.0.0.1:${PROM_PORT:-9092}/api/v1/query?query=up" >/dev/null 2>&1; then
    prom_start "${PROM_PORT:-9092}"
  fi
  local enc
  enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$expr")
  { curl -sf "http://127.0.0.1:${PROM_PORT:-9092}/api/v1/query?query=${enc}" 2>/dev/null || true; } | python3 -c '
import json,sys
try:
    r=json.load(sys.stdin)["data"]["result"]
    print(r[0]["value"][1] if r else "0")
except Exception:
    print("0")
'
}

prom_wait() {
  if [ -z "${1:-}" ]; then
    sleep 16
    return 0
  fi
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    sleep "$1"
    return 0
  fi

  local expr="$1"
  local target="${2:-}"
  local timeout="${3:-30}"
  local start_time
  start_time="$(date +%s)"

  while true; do
    local val
    val="$(promval "$expr")"
    if [ -z "$target" ]; then
      if [ "$(awk "BEGIN {print (${val:-0} > 0) ? 1 : 0}")" -eq 1 ]; then
        return 0
      fi
    else
      if [ "$val" = "$target" ] || [ "$(awk "BEGIN {print (${val:-0} >= ${target:-0}) ? 1 : 0}")" -eq 1 ]; then
        return 0
      fi
    fi

    local now
    now="$(date +%s)"
    if [ $((now - start_time)) -ge "$timeout" ]; then
      return 1
    fi
    sleep 2
  done
}
