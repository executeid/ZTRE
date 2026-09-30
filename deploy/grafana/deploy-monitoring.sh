#!/usr/bin/env bash
# ==============================================================================
# ZTRE Monitoring Stack Deployment
# Deploys Prometheus + Grafana with ZTRE dashboard and alert rules
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTRE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COLOR_GREEN="\033[0;32m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"
log_info()  { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"; }
log_pass()  { echo -e "${COLOR_GREEN}[DONE]${COLOR_RESET} $*"; }

echo "======================================================================"
echo "    ZTRE Monitoring Stack: Prometheus + Grafana + Alert Rules          "
echo "======================================================================"

# 1. Create namespace
log_info "Creating monitoring namespace..."
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

# 1a. Pre-stage images onto the worker node (cluster nodes have no registry access)
# These images are imported into containerd; the Deployments use imagePullPolicy: Never.
BASTION_HAS_DOCKER=$(command -v docker >/dev/null 2>&1 && echo yes || echo no)
if [ "$BASTION_HAS_DOCKER" = "yes" ]; then
    for img in grafana/grafana:10.4.0 prom/prometheus:v2.51.0; do
        if ! ssh -o BatchMode=yes -o ConnectTimeout=5 node2@10.91.128.11 \
              "sudo ctr -n k8s.io images ls | grep -q '${img%%:*}:${img##*:}'" 2>/dev/null; then
            log_info "Pre-staging image onto worker: $img"
            docker pull "$img" >/dev/null 2>&1 || true
            docker save "$img" | ssh -o StrictHostKeyChecking=no node2@10.91.128.11 \
              'sudo ctr -n k8s.io images import -' >/dev/null 2>&1 || true
        fi
    done
else
    log_info "docker not found on bastion; assuming images already staged on the worker node."
fi

# 2. Create ZTRE dashboard ConfigMap from the JSON file
log_info "Loading ZTRE Grafana dashboard..."
kubectl create configmap ztre-grafana-dashboard \
  --from-file=ztre-overview.json="$ZTRE_ROOT/deploy/grafana-dashboard-provisioned.json" \
  -n monitoring \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Deploy Prometheus (config + rules + deployment + RBAC)
log_info "Deploying Prometheus..."
kubectl apply -f "$SCRIPT_DIR/prometheus-rules.yaml"
kubectl apply -f "$SCRIPT_DIR/prometheus-deployment.yaml"

# 4. Deploy Grafana
log_info "Deploying Grafana..."
kubectl apply -f "$SCRIPT_DIR/grafana-deployment.yaml"

# 5. Wait for rollouts
log_info "Waiting for Prometheus to become ready..."
kubectl rollout status deployment/prometheus -n monitoring --timeout=120s

log_info "Waiting for Grafana to become ready..."
kubectl rollout status deployment/grafana -n monitoring --timeout=120s

# 6. Get access info
GRAFANA_NODE_PORT=$(kubectl get svc grafana -n monitoring -o jsonpath='{.spec.ports[0].nodePort}')
WORKER_IP=$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

echo ""
echo "======================================================================"
log_pass "Monitoring stack deployed successfully!"
echo ""
echo "  Grafana URL:      http://${WORKER_IP}:${GRAFANA_NODE_PORT}"
echo "  Grafana Login:    admin / ztre-admin"
echo "  Dashboard:        ZTRE > ZTRE Security Overview"
echo ""
echo "  Prometheus:       kubectl port-forward svc/prometheus 9090:9090 -n monitoring"
echo ""
echo "  Next steps:"
echo "    1. Open Grafana in browser"
echo "    2. Navigate to Dashboards > ZTRE > ZTRE Security Overview"
echo "    3. Run threat simulation: ./tests/cluster/stage5_simulation.sh"
echo "    4. Take screenshots of dashboards during attack"
echo "======================================================================"
