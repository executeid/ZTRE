#!/usr/bin/env bash
# =============================================================================
# ZTRE Cluster Test — Scenario 2: Multi-Stage Kill Chain
# Implements doc/ADVANCED_TEST_PLAN.md v1.4.0 §3.2 & §9.2
#
# Progressive risk escalation evaluation via vulnerable-web HTTP NodePort:
#   Stage 1: Reconnaissance (id, uname -a, cat /etc/hosts)
#            -> Context ANOMALOUS (C=100), default severity (S=20), Asset low (A=25)
#            -> Expected score: 45.0 (YELLOW zone: LOG_AND_ALERT)
#   Stage 2: Lateral Probe (wget -q -O - http://database:5432)
#            -> Context ANOMALOUS (C=100), curl_download severity (S=80), Asset low (A=25)
#            -> Expected score: 75.0 (RED zone: AUTO_CONTAINMENT)
#   Stage 3: Privilege Escalation (chmod +s /bin/sh)
#            -> Context ANOMALOUS (C=100), chmod_suid severity (S=90), Asset low (A=25)
#            -> Expected score: 80.0 (RED zone: AUTO_CONTAINMENT)
#
# Requirements:
#   - Bastion has NO nc and NO ping (uses curl, python3, ssh, kubectl)
#   - Inside pod: BusyBox-safe commands
#   - Sourced via lib/common.sh
# =============================================================================
set -uo pipefail

# ---- Directory and Environment Setup ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd || pwd)"

# Source shared library if present
if [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/lib/common.sh"
elif [ -f "$REPO_ROOT/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$REPO_ROOT/lib/common.sh"
elif [ -f "lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "lib/common.sh"
elif [ -f "$REPO_ROOT/tests/cluster/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$REPO_ROOT/tests/cluster/lib/common.sh"
elif [ -f "${SCRIPT_DIR}/advanced_common_setup.sh" ]; then
  # shellcheck source=/dev/null
  source "${SCRIPT_DIR}/advanced_common_setup.sh"
fi

# ---- Configuration & Defaults (Ground Truth Cluster Values) -----------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
NODEPORT="${NODEPORT:-30080}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

# Resolve relative EVIDENCE_DIR to REPO_ROOT regardless of CWD
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="$REPO_ROOT/$EVIDENCE_DIR" ;;
esac
mkdir -p "$EVIDENCE_DIR"
LOG="${LOG:-$EVIDENCE_DIR/run-$TS.log}"

# ---- Helper Fallbacks (if not supplied by lib/common.sh) ---------------------
if ! declare -F say >/dev/null 2>&1; then
  say() { echo "$*" | tee -a "$LOG"; }
fi

if ! declare -F hdr >/dev/null 2>&1; then
  hdr() { say ""; say "============================================================"; say "$*"; say "============================================================"; }
fi

if ! declare -F pass >/dev/null 2>&1; then
  pass() { say "[PASS] $*"; }
fi

if ! declare -F fail >/dev/null 2>&1; then
  fail() { say "[FAIL] $*"; }
fi

if ! declare -F warn >/dev/null 2>&1; then
  warn() { say "[WARN] $*"; }
fi

if ! declare -F agent_logs >/dev/null 2>&1; then
  agent_logs() {
    local tail="${1:-2000}"
    kubectl logs -n "$AGENT_NS" -l "$AGENT_LABEL" --tail="$tail" 2>/dev/null
  }
fi

if ! declare -F get_pod >/dev/null 2>&1; then
  get_pod() {
    local app="$1"
    local pod
    pod="$(kubectl get pod -n "$NS" -l "app=${app}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [ -z "$pod" ]; then
      pod="$(kubectl get pod -n "$NS" "${app}" -o jsonpath='{.metadata.name}' 2>/dev/null || true)"
    fi
    echo "$pod"
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

# =============================================================================
# run_scenario2: Main Scenario Execution Function
# =============================================================================
run_scenario2() {
  hdr "PHASE 3: Scenario 2 - Multi-Stage Kill Chain"

  # Step 1: Discover target pod (vulnerable-web)
  local web_pod
  web_pod=$(get_pod vulnerable-web)
  if [ -z "$web_pod" ]; then
    say "[SC2][WARN] vulnerable-web pod not immediately found; checking readiness..."
    if declare -F wait_ready >/dev/null 2>&1; then
      wait_ready vulnerable-web 30 || true
      web_pod=$(get_pod vulnerable-web)
    fi
  fi

  if [ -z "$web_pod" ]; then
    fail "[SC2] vulnerable-web pod not found in namespace $NS"
    return 1
  fi
  say "[SC2] Target workload pod: $web_pod"

  # Step 2: Test reachability to NodePort endpoint
  say "[SC2] Checking HTTP connectivity: http://$WORKER_IP:$NODEPORT/exec?cmd=id"
  local probe_ok=false
  for attempt in 1 2 3; do
    local resp
    resp=$(curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=id" 2>/dev/null || true)
    if [ -n "$resp" ]; then
      say "[SC2] Endpoint reachable (attempt $attempt): $(echo "$resp" | head -n 1)"
      probe_ok=true
      break
    fi
    sleep 2
  done
  if [ "$probe_ok" != "true" ]; then
    warn "[SC2] NodePort http://$WORKER_IP:$NODEPORT/exec?cmd=id not responding, continuing anyway..."
  fi

  # Step 3: Reset agent deduplication cache and clear existing quarantine labels
  reset_agent_and_wait vulnerable-web

  # Step 4: Verify starting clean state
  local init_quar
  init_quar=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || echo "")
  if [ "$init_quar" = "true" ]; then
    say "[SC2][WARN] Initial quarantine label still 'true', clearing explicitly..."
    kubectl label pod -n "$NS" "$web_pod" ztre/quarantine- --overwrite >/dev/null 2>&1 || true
    sleep 1
  fi

  # Step 5: Stage 1 — Reconnaissance (id, uname -a, cat /etc/hosts)
  say "[SC2-stage1] Reconnaissance: firing id, uname -a, cat /etc/hosts (expect YELLOW ~45; no GREEN tier under live model)"
  curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=id" >/dev/null 2>&1 || true
  curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=uname+-a" >/dev/null 2>&1 || true
  curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=cat+/etc/hosts" >/dev/null 2>&1 || true
  sleep 4

  local sc2_stage1=""
  sc2_stage1=$(agent_logs 2000 | jq -rR --arg pod "$web_pod" '
    fromjson? | select((.pod == $pod or (.pod // "" | contains("vulnerable-web")) or (.msg // "" | contains("vulnerable-web"))) and .action == "LOG_AND_ALERT") | .risk_score
  ' 2>/dev/null | tail -1)
  if [ -z "$sc2_stage1" ]; then
    sc2_stage1=$(agent_logs 2000 | grep -E "vulnerable-web|$web_pod" | jq -rR 'fromjson? | select(.action=="LOG_AND_ALERT") | .risk_score' 2>/dev/null | tail -1)
  fi

  local stage1_quar
  stage1_quar=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || echo "")
  say "[SC2-stage1] Observed recon score : ${sc2_stage1:-<none>} (expected: ~45 YELLOW, action=LOG_AND_ALERT)"
  say "[SC2-stage1] Quarantined after recon: ${stage1_quar:-no} (expected: no)"

  # Step 6: Stage 2 — Lateral Probe (wget database:5432)
  say "[SC2-stage2] Lateral Probe: firing wget -q -O - http://database:5432 (expect RED ~75)"
  curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=wget+-q+-O+-+http://database:5432" >/dev/null 2>&1 || true
  sleep 4

  local sc2_stage2=""
  sc2_stage2=$(agent_logs 2000 | jq -rR --arg pod "$web_pod" '
    fromjson? | select((.pod == $pod or (.pod // "" | contains("vulnerable-web")) or (.msg // "" | contains("vulnerable-web"))) and ((.binary // "") | endswith("wget"))) | .risk_score
  ' 2>/dev/null | tail -1)
  if [ -z "$sc2_stage2" ]; then
    sc2_stage2=$(agent_logs 2000 | grep -E "vulnerable-web|$web_pod" | jq -rR 'fromjson? | select(.binary=="/usr/bin/wget" or ((.binary // "") | endswith("wget"))) | .risk_score' 2>/dev/null | tail -1)
  fi
  say "[SC2-stage2] Observed probe score : ${sc2_stage2:-<none>} (expected: ~75 RED, binary=/usr/bin/wget)"

  # Step 7: Stage 3 — Privilege Escalation (chmod +s /bin/sh)
  say "[SC2-stage3] Privilege Escalation: firing chmod +s /bin/sh (expect RED ~80)"
  curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=chmod+%2Bs+/bin/sh" >/dev/null 2>&1 || true
  sleep 6

  local sc2_stage3=""
  sc2_stage3=$(agent_logs 2000 | jq -rR --arg pod "$web_pod" '
    fromjson? | select((.pod == $pod or (.pod // "" | contains("vulnerable-web")) or (.msg // "" | contains("vulnerable-web"))) and ((.binary // "") | endswith("chmod"))) | .risk_score
  ' 2>/dev/null | tail -1)
  if [ -z "$sc2_stage3" ]; then
    sc2_stage3=$(agent_logs 2000 | grep -E "vulnerable-web|$web_pod" | jq -rR 'fromjson? | select(.binary=="/bin/chmod" or ((.binary // "") | endswith("chmod"))) | .risk_score' 2>/dev/null | tail -1)
  fi
  say "[SC2-stage3] Observed exploit score: ${sc2_stage3:-<none>} (expected: ~80 RED, binary=/bin/chmod)"

  # Step 8: Post-killchain workload inspection
  local sc2_label
  sc2_label=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || echo "")
  local sc2_phase
  sc2_phase=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
  local sc2_restarts
  sc2_restarts=$(kubectl get pod -n "$NS" "$web_pod" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

  # Optional containment log extraction
  local sc2_containment_log
  sc2_containment_log=$(agent_logs 2000 | jq -rR --arg pod "$web_pod" '
    fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY" and (.pod == $pod or (.pod // "" | contains("vulnerable-web")) or (.msg // "" | contains("vulnerable-web")))) | "score=\(.risk_score) latency=\(.latency)"
  ' 2>/dev/null | tail -1)

  # Step 9: Evaluate verdict
  local verdict="FAIL"
  if [ "$sc2_label" = "true" ]; then
    verdict="PASS"
  fi

  say ""
  say "============================================================"
  say "Scenario 2: Multi-Stage Kill Chain Results:"
  say "  Target Pod             : $web_pod"
  say "  Recon Score (stage 1)  : ${sc2_stage1:-<none>} (expect ~45 YELLOW)"
  say "  Probe Score (stage 2)  : ${sc2_stage2:-<none>} (expect ~75 RED)"
  say "  Exploit Score (stage 3): ${sc2_stage3:-<none>} (expect ~80 RED)"
  say "  Containment Log Event  : ${sc2_containment_log:-<none>}"
  say "  Final Quarantine Label : ${sc2_label:-<none>} (expect: true)"
  say "  Pod Phase              : $sc2_phase (expect: Running)"
  say "  Container Restarts     : $sc2_restarts (expect: 0)"
  say "  Scenario 2 Verdict     : $verdict"
  say "============================================================"

  # Step 10: Write JSON result fragments
  local json_fragment="$EVIDENCE_DIR/scenario2_result-$TS.json"
  local json_canonical="$EVIDENCE_DIR/scenario2_result.json"

  jq -n \
    --arg ts "$TS" \
    --arg scenario "scenario2_killchain" \
    --arg verdict "$verdict" \
    --arg pod "$web_pod" \
    --arg worker_ip "$WORKER_IP" \
    --arg nodeport "$NODEPORT" \
    --arg recon "${sc2_stage1:-}" \
    --arg probe "${sc2_stage2:-}" \
    --arg exploit "${sc2_stage3:-}" \
    --arg quar "${sc2_label:-}" \
    --arg phase "$sc2_phase" \
    --arg restarts "$sc2_restarts" \
    --arg cont_log "${sc2_containment_log:-}" \
    '{
      timestamp: $ts,
      scenario: $scenario,
      verdict: $verdict,
      target_pod: $pod,
      worker_ip: $worker_ip,
      nodeport: ($nodeport | tonumber? // $nodeport),
      recon_score: (if $recon == "" then null else ($recon | tonumber? // $recon) end),
      probe_score: (if $probe == "" then null else ($probe | tonumber? // $probe) end),
      exploit_score: (if $exploit == "" then null else ($exploit | tonumber? // $exploit) end),
      quarantine_label: $quar,
      quarantined: ($quar == "true"),
      phase: $phase,
      restarts: ($restarts | tonumber? // $restarts),
      containment_log: (if $cont_log == "" then null else $cont_log end),
      scenario2: {
        recon_score: $recon,
        probe_score: $probe,
        exploit_score: $exploit,
        quarantine_label: $quar,
        phase: $phase,
        restarts: $restarts,
        verdict: $verdict
      }
    }' > "$json_fragment" 2>/dev/null || true

  cp -f "$json_fragment" "$json_canonical" 2>/dev/null || true
  say "[SC2] Result fragment written: $json_fragment"
  say "[SC2] Canonical result written: $json_canonical"

  if [ "$verdict" = "PASS" ]; then
    return 0
  else
    return 1
  fi
}

# Execute automatically if invoked directly as a script
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  run_scenario2 "$@"
fi
