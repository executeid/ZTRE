#!/usr/bin/env bash
# =============================================================================
# ZTRE Master Test Orchestrator: run_all_scenarios.sh
# Drives Phase 0 (Pre-flight), Phase 1 (Deploy Workload), and Scenarios 1 to 4
# in sequence, then aggregates evidence fragments into a summary JSON report.
#
# References:
#   - doc/ADVANCED_TEST_PLAN.md v1.5.0
#   - PRD NFR-01: Containment latency SLA (< 50ms)
# =============================================================================
set -uo pipefail

# ---- Directory and Environment Setup ----------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd -P || pwd -P)"

# Source shared library lib/common.sh
if [ -f "$REPO_ROOT/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$REPO_ROOT/lib/common.sh"
elif [ -f "$SCRIPT_DIR/lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/lib/common.sh"
elif [ -f "lib/common.sh" ]; then
  # shellcheck source=/dev/null
  source "lib/common.sh"
fi

# ---- Default Configuration (Cluster Ground Truth) ---------------------------
export NS="${NS:-ztre-test}"
export AGENT_NS="${AGENT_NS:-ztre-system}"
export AGENT_LABEL="${AGENT_LABEL:-app.kubernetes.io/name=ztre-agent}"
export WORKER_IP="${WORKER_IP:-10.91.128.11}"
export BASTION_IP="${BASTION_IP:-10.91.128.10}"
export NODEPORT="${NODEPORT:-30080}"
export EXFIL_PORT="${EXFIL_PORT:-9999}"
export TS="${TS:-$(date +%Y%m%d-%H%M%S)}"

# Resolve relative EVIDENCE_DIR to absolute path via REPO_ROOT
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="$REPO_ROOT/$EVIDENCE_DIR" ;;
esac
mkdir -p "$EVIDENCE_DIR"
export EVIDENCE_DIR
export LOG="${LOG:-$EVIDENCE_DIR/run-$TS.log}"

# ---- Fallback Logging Helpers -----------------------------------------------
if ! declare -F say >/dev/null 2>&1; then
  say() { echo "$*" | tee -a "$LOG"; }
fi

if ! declare -F hdr >/dev/null 2>&1; then
  hdr() { say ""; say "============================================================"; say "$*"; say "============================================================"; }
fi

# Helper to find latest JSON fragment for a scenario
find_fragment() {
  local pattern="$1"
  local f
  for f in "$EVIDENCE_DIR"/${pattern}*${TS}*.json; do
    if [ -f "$f" ]; then
      echo "$f"
      return 0
    fi
  done
  for f in "$EVIDENCE_DIR"/${pattern}*.json; do
    if [ -f "$f" ]; then
      echo "$f"
      return 0
    fi
  done
  echo "/dev/null"
}

# =============================================================================
# Execution Pipeline
# =============================================================================
hdr "ZTRE ADVANCED OUTSIDER SIMULATION SUITE"
say "[suite] Timestamp    : $TS"
say "[suite] Namespace    : $NS (Agent NS: $AGENT_NS)"
say "[suite] Worker Node  : $WORKER_IP (NodePort: $NODEPORT)"
say "[suite] Bastion Host : $BASTION_IP (Exfil Port: $EXFIL_PORT)"
say "[suite] Evidence Dir : $EVIDENCE_DIR"
say "[suite] Log File     : $LOG"

# Sourcing Phase 0 & 1 setup script
SETUP_SCRIPT="$SCRIPT_DIR/advanced_common_setup.sh"
if [ ! -f "$SETUP_SCRIPT" ]; then
  say "[FAIL] Setup script $SETUP_SCRIPT not found"
  exit 1
fi
# shellcheck source=/dev/null
source "$SETUP_SCRIPT"

# Phase 0: Pre-flight
run_preflight || { say "[FAIL] Phase 0: Pre-flight verification failed"; exit 1; }

# Phase 1: Deploy workload
run_deploy_web || { say "[FAIL] Phase 1: Deploy vulnerable-web workload failed"; exit 1; }

# Track individual scenario status codes
RC_SC1=0
RC_SC2=0
RC_SC3=0
RC_SC4=0

# Phase 2: Scenario 1 - HTTP Ingress RCE
hdr "PHASE 2: Run Scenario 1 - HTTP Ingress RCE"
SC1_SCRIPT="$SCRIPT_DIR/scenario1_ingress_rce.sh"
if [ -f "$SC1_SCRIPT" ]; then
  # shellcheck source=/dev/null
  source "$SC1_SCRIPT"
  run_scenario1 || RC_SC1=$?
else
  say "[WARN] Scenario 1 script $SC1_SCRIPT not found"
  RC_SC1=127
fi

# Phase 3: Scenario 2 - Multi-Stage Kill Chain
hdr "PHASE 3: Run Scenario 2 - Multi-Stage Kill Chain"
SC2_SCRIPT="$SCRIPT_DIR/scenario2_killchain.sh"
if [ -f "$SC2_SCRIPT" ]; then
  # shellcheck source=/dev/null
  source "$SC2_SCRIPT"
  run_scenario2 || RC_SC2=$?
else
  say "[WARN] Scenario 2 script $SC2_SCRIPT not found"
  RC_SC2=127
fi

# Phase 4: Scenario 3 - Living-Off-The-Land Evasion
hdr "PHASE 4: Run Scenario 3 - Living-Off-The-Land Evasion"
SC3_SCRIPT="$SCRIPT_DIR/scenario3_evasion.sh"
if [ -f "$SC3_SCRIPT" ]; then
  # shellcheck source=/dev/null
  source "$SC3_SCRIPT"
  run_scenario3 || RC_SC3=$?
else
  say "[WARN] Scenario 3 script $SC3_SCRIPT not found"
  RC_SC3=127
fi

# Phase 5: Scenario 4 - Exfiltration Race Window
hdr "PHASE 5: Run Scenario 4 - Exfiltration Race Window"
SC4_SCRIPT="$SCRIPT_DIR/scenario4_exfil_race.sh"
if [ -f "$SC4_SCRIPT" ]; then
  # shellcheck source=/dev/null
  source "$SC4_SCRIPT"
  run_scenario4 || RC_SC4=$?
else
  say "[WARN] Scenario 4 script $SC4_SCRIPT not found"
  RC_SC4=127
fi

# Phase 6: Teardown & Results Aggregation
hdr "PHASE 6: Teardown & Export"

say "[cleanup] clearing quarantine labels across namespace $NS"
kubectl label pod -n "$NS" --all ztre/quarantine- --overwrite >/dev/null 2>&1 || true
say "[cleanup] quarantine labels cleared"

SC1_JSON=$(find_fragment "scenario1")
SC2_JSON=$(find_fragment "scenario2")
SC3_JSON=$(find_fragment "scenario3")
SC4_JSON=$(find_fragment "scenario4")

SUMMARY="$EVIDENCE_DIR/summary-$TS.json"
CANONICAL_SUMMARY="$EVIDENCE_DIR/summary.json"

jq -n \
  --arg ts "$TS" \
  --slurpfile sc1 "$SC1_JSON" \
  --slurpfile sc2 "$SC2_JSON" \
  --slurpfile sc3 "$SC3_JSON" \
  --slurpfile sc4 "$SC4_JSON" \
  '{
    timestamp: $ts,
    scenario1: (if ($sc1 | length) > 0 then ($sc1[0].scenario1 // $sc1[0]) else {} end),
    scenario2: (if ($sc2 | length) > 0 then ($sc2[0].scenario2 // $sc2[0]) else {} end),
    scenario3: (if ($sc3 | length) > 0 then ($sc3[0].scenario3 // $sc3[0]) else {} end),
    scenario4: (if ($sc4 | length) > 0 then ($sc4[0].scenario4 // $sc4[0]) else {} end)
  }' > "$SUMMARY" 2>/dev/null || {
    say "[WARN] jq aggregation failed, writing fallback summary"
    echo "{\"timestamp\":\"$TS\",\"error\":\"aggregation_failed\"}" > "$SUMMARY"
  }

cp -f "$SUMMARY" "$CANONICAL_SUMMARY" 2>/dev/null || true

say "[export] summary written   : $SUMMARY"
say "[export] canonical summary : $CANONICAL_SUMMARY"
say "[export] full log          : $LOG"

# Check for exfil binary
RECV_FILE="$EVIDENCE_DIR/race_exfil-$TS.bin"
if [ ! -f "$RECV_FILE" ]; then
  RECV_FILE=$(ls -t "$EVIDENCE_DIR"/race_exfil*.bin 2>/dev/null | head -1 || true)
fi
if [ -n "$RECV_FILE" ] && [ -f "$RECV_FILE" ]; then
  say "[export] exfil dump        : $RECV_FILE"
fi

hdr "SUITE VERDICT SUMMARY"
sc1_line=$( [ "$RC_SC1" -eq 0 ] && echo "PASS" || { [ "$RC_SC1" -eq 2 ] && echo "PARTIAL_PASS" || echo "FAIL ($RC_SC1)"; } )
say "  Scenario 1 (HTTP Ingress RCE)       : $sc1_line"
say "  Scenario 2 (Multi-Stage Kill Chain) : $( [ "$RC_SC2" -eq 0 ] && echo "PASS" || echo "FAIL ($RC_SC2)" )"
say "  Scenario 3 (LotL Evasion Matrix)    : $( [ "$RC_SC3" -eq 0 ] && echo "PASS" || echo "FAIL ($RC_SC3)" )"
say "  Scenario 4 (Exfiltration Race)      : $( [ "$RC_SC4" -eq 0 ] && echo "PASS" || echo "FAIL ($RC_SC4)" )"
say "============================================================"

OVERALL_RC=0
if [ "$RC_SC1" -ne 0 ] || [ "$RC_SC2" -ne 0 ] || [ "$RC_SC3" -ne 0 ] || [ "$RC_SC4" -ne 0 ]; then
  OVERALL_RC=1
fi

exit "$OVERALL_RC"
