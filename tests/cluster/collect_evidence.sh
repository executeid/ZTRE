#!/usr/bin/env bash
# ==============================================================================
# ZTRE Master Evidence Collection Script
# Runs all evidence collection in order. You take screenshots at each pause.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTRE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ZTRE_ROOT"

COLOR_GREEN="\033[0;32m"
COLOR_BLUE="\033[0;34m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_RESET="\033[0m"
log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[DONE]${COLOR_RESET} $*"; }
log_action(){ echo -e "${COLOR_YELLOW}[ACTION]${COLOR_RESET} $*"; }
log_phase() { echo -e "${COLOR_CYAN}[PHASE]${COLOR_RESET} $*"; }

pause_for_screenshot() {
    echo ""
    log_action ">>> SCREENSHOT POINT: $1"
    log_action ">>> Save to: evidence/screenshots/$2"
    echo ""
    read -p "    Press ENTER after taking screenshot (or 's' to skip)... " response
    if [ "${response:-}" != "s" ]; then
        log_pass "Screenshot noted: $2"
    fi
}

mkdir -p evidence/{screenshots,recordings,flows,soak,concurrent}

echo "======================================================================"
echo "    ZTRE Master Evidence Collection                                    "
echo "    Take screenshots when prompted. Press ENTER to continue.           "
echo "======================================================================"
echo ""

# ===========================================================================
# PHASE 1: Deploy Monitoring Stack
# ===========================================================================
log_phase "PHASE 1: Deploy Monitoring Stack (Prometheus + Grafana)"
echo ""
read -p "Deploy monitoring stack? [Y/n] " deploy_mon
if [ "${deploy_mon:-Y}" != "n" ]; then
    bash deploy/grafana/deploy-monitoring.sh
    echo ""
    pause_for_screenshot \
        "Open Grafana dashboard (ZTRE Security Overview) - empty state before any attacks" \
        "grafana-dashboard-empty.png"
fi

# ===========================================================================
# PHASE 2: Run Threat Simulation with Dashboard Active
# ===========================================================================
log_phase "PHASE 2: Run Stage 5 Threat Simulation (watch Grafana during this)"
echo ""
log_action "Open Grafana dashboard in browser NOW before continuing."
log_action "Set time range to 'Last 15 minutes' and auto-refresh to 5s."
echo ""
read -p "Ready to run threat simulation? [Y/n] " run_sim
if [ "${run_sim:-Y}" != "n" ]; then
    bash tests/cluster/stage5_simulation.sh
    echo ""
    pause_for_screenshot \
        "Grafana dashboard showing attack spike - events ingested, classification breakdown, containment actions" \
        "grafana-during-attack.png"
    
    pause_for_screenshot \
        "Grafana risk score distribution panel showing Red zone entries" \
        "grafana-risk-distribution.png"
    
    pause_for_screenshot \
        "Grafana containment timeline panel showing quarantine events" \
        "grafana-containment-timeline.png"
    
    pause_for_screenshot \
        "Grafana agent CPU/Memory panels showing resource usage within limits" \
        "grafana-agent-resources.png"
fi

# ===========================================================================
# PHASE 3: Prometheus Alert Rules Evidence
# ===========================================================================
log_phase "PHASE 3: Prometheus Alert Rules"
echo ""
PROM_POD=$(kubectl get pods -n monitoring -l app=prometheus -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$PROM_POD" ]; then
    log_info "Checking Prometheus alert rules..."
    kubectl port-forward svc/prometheus 9091:9090 -n monitoring >/dev/null 2>&1 &
    PF_PID=$!
    sleep 2
    
    curl -sf http://localhost:9091/api/v1/rules 2>/dev/null | python3 -m json.tool 2>/dev/null | head -30 || true
    
    pause_for_screenshot \
        "Prometheus Alerts page (http://localhost:9091/alerts) showing ZTRE alert rules" \
        "prometheus-alert-rules.png"
    
    kill $PF_PID 2>/dev/null || true
fi

# ===========================================================================
# PHASE 4: Hubble Flow Capture
# ===========================================================================
log_phase "PHASE 4: Hubble Network Flow Capture (before/after quarantine)"
echo ""
read -p "Run Hubble flow capture? [Y/n] " run_hubble
if [ "${run_hubble:-Y}" != "n" ]; then
    bash tests/cluster/hubble_flow_capture.sh || log_info "Hubble capture completed (or skipped if unavailable)"
fi

# ===========================================================================
# PHASE 5: Concurrent Multi-Attack Test
# ===========================================================================
log_phase "PHASE 5: Concurrent Multi-Attack Test"
echo ""
read -p "Run concurrent attack test? [Y/n] " run_concurrent
if [ "${run_concurrent:-Y}" != "n" ]; then
    bash tests/cluster/concurrent_attack_test.sh
    
    pause_for_screenshot \
        "Grafana dashboard showing 3 simultaneous containment actions" \
        "grafana-concurrent-containments.png"
fi

# ===========================================================================
# PHASE 6: Forensic Inspection Evidence
# ===========================================================================
log_phase "PHASE 6: Forensic Artifact Inspection (quarantined pod)"
echo ""

# Find a quarantined pod
Q_POD=$(kubectl get pods -n ztre-test -l ztre/quarantine=true -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$Q_POD" ]; then
    log_info "Inspecting quarantined pod: $Q_POD"
    echo ""
    echo "--- Pod Status ---"
    kubectl get pod "$Q_POD" -n ztre-test -o wide
    echo ""
    echo "--- Process Memory Maps (first 5 lines) ---"
    kubectl exec -n ztre-test "$Q_POD" -- cat /proc/1/maps 2>/dev/null | head -5
    echo ""
    echo "--- Open File Descriptors ---"
    kubectl exec -n ztre-test "$Q_POD" -- ls -la /proc/1/fd/ 2>/dev/null | head -10
    echo ""
    echo "--- Network Test (should be blocked) ---"
    kubectl exec -n ztre-test "$Q_POD" -- /bin/sh -c "nc -z -w 2 10.91.128.11 5432; echo exit:\$?" 2>/dev/null || echo "(command may timeout - network blocked)"
    echo ""
    
    pause_for_screenshot \
        "Terminal showing quarantined pod: Running/0 restarts, /proc/1/maps intact, network blocked" \
        "forensic-inspection.png"
else
    log_info "No quarantined pods found. Run threat simulation first."
fi

# ===========================================================================
# PHASE 7: Soak Test (Optional - takes 1 hour)
# ===========================================================================
log_phase "PHASE 7: Soak Test (1-hour endurance run)"
echo ""
echo "  This test runs for 1 hour with periodic attack injection."
echo "  It produces evidence/soak/metrics.csv for resource trend analysis."
echo ""
read -p "Run 1-hour soak test now? [y/N] " run_soak
if [ "${run_soak:-N}" = "y" ] || [ "${run_soak:-N}" = "Y" ]; then
    bash tests/cluster/soak_test.sh
    
    pause_for_screenshot \
        "Grafana agent CPU/Memory panels over 1-hour soak test window" \
        "grafana-soak-resources.png"
else
    log_info "Skipping soak test. Run manually: bash tests/cluster/soak_test.sh"
fi

# ===========================================================================
# SUMMARY
# ===========================================================================
echo ""
echo "======================================================================"
echo "    Evidence Collection Complete                                       "
echo "======================================================================"
echo ""
echo "  Evidence directory:"
ls -la evidence/screenshots/ 2>/dev/null || echo "    (no screenshots saved yet)"
echo ""
ls -la evidence/flows/ 2>/dev/null || echo "    (no flow captures yet)"
echo ""
ls -la evidence/concurrent/ 2>/dev/null || echo "    (no concurrent test results yet)"
echo ""
ls -la evidence/soak/ 2>/dev/null || echo "    (no soak test data yet)"
echo ""
echo "  Generated artifacts:"
echo "    - evidence/concurrent/parallel-containment-results.json"
echo "    - evidence/soak/metrics.csv"
echo "    - evidence/flows/pre-quarantine-flows.json"
echo "    - evidence/flows/post-quarantine-drops.json"
echo ""
echo "  Remember to save your screenshots to evidence/screenshots/"
echo "======================================================================"
