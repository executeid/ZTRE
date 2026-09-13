# Current Infrastructure Condition & Discovery Report

**Generated Date:** 2026-09-12  
**Target Environment:** `bastion` (`10.91.128.10`) & Kubernetes Cluster  
**Project:** Zero-Trust Runtime Enforcement (ZTRE)  
**Reference Document:** [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md)

---

## 1. Executive Summary

A live discovery of the development environment and Kubernetes cluster was conducted from `bastion@bastion`. 
The core eBPF foundation (**Cilium CNI** and **Tetragon**) is already operational in the cluster and actively capturing kernel events. 
However, key project-specific configurations (dedicated namespaces, Cilium quarantine policies, Tetragon tracing policies, RBAC, and the Python application scaffolding) have not yet been provisioned.

> **Topology Revision Note:**  
> The original roadmap target of 1 control-plane + 2 worker nodes has been revised: **the existing 2-node cluster (1 control-plane + 1 worker node) is approved and sufficient for this project**.

---

## 2. Cluster & Node Topology

| Host / Node | Role | IP Address | OS / Kernel | Container Runtime | Status |
|---|---|---|---|---|---|
| **bastion** | Jump host / Dev CLI | `10.91.128.10` | Ubuntu Linux (kernel 6.8.0-52-generic) | None (needs Docker/Podman) | Reachable via SSH, full `sudo` privileges |
| **akmal-vm-node1** | Control-plane | `10.91.128.9` | Rocky Linux 9.8 (kernel 5.14.0-687.42.1.el9_8.x86_64) | containerd v2.3.4 | `Ready`, Taint: `node-role.kubernetes.io/control-plane:NoSchedule` |
| **akmal-vm-node2** | Worker node | `10.91.128.11` | Rocky Linux 9.8 (kernel 5.14.0-687.42.1.el9_8.x86_64) | containerd v2.3.4 | `Ready`, No taints (all workload pods run here) |

### Cluster Specifications
- **Kubernetes Version:** `v1.30.14`
- **Control Plane API:** `https://10.91.128.9:6443`
- **Node Resources:**
  - `akmal-vm-node1`: 8 vCPUs, 16 GB RAM, ~200 GB disk
  - `akmal-vm-node2`: 8 vCPUs, 16 GB RAM, ~200 GB disk

---

## 3. Installed Components & Discovery Details

### 3.1 Cilium CNI (Networking & Enforcement Engine)
- **Status:** Running and healthy (`cilium status` OK).
- **Helm Release:** `cilium` v1.20.1 in `kube-system` (Revision 8).
- **Encryption:** Enabled (`WireGuard`).
- **Endpoints & Pods:** 9/9 cluster pods managed by Cilium.
- **Current Flags & Settings:**
  - `kube-proxy-replacement`: `false` (Standard `kube-proxy` is absent; roadmap calls for `strict`).
  - `routing-mode`: `tunnel` (VXLAN).
- **Existing Network Policies:**
  - Namespace `intro`: `rule1` (Cilium Star Wars demo: `deathstar`, `tiefighter`, `xwing`).
  - **Gap:** `ztre-quarantine-policy` is **not deployed**.

### 3.2 Tetragon (eBPF Security Observability Engine)
- **Status:** Running and healthy (`tetragon status` OK).
- **Helm Release:** `tetragon` v1.7.1 in `kube-system`.
- **DaemonSet Pods:**
  - `tetragon-lnlmb` on `akmal-vm-node1`
  - `tetragon-hm5bg` on `akmal-vm-node2`
- **Socket & gRPC Access:**
  - Server address: `unix:///var/run/tetragon/tetragon.sock`
  - Host mount: `/var/run/tetragon`
- **Live Event Emission Test:**
  - Tested on `akmal-vm-node2` with a temporary pod.
  - Tetragon successfully intercepted process execution events (`PROCESS_EXEC`, `PROCESS_EXIT`).
  - Emits: `process.binary`, `process.pid`, `parent.binary`, `pod.namespace`, `pod.name`.
- **Gap:** No `TracingPolicy` CRDs deployed (`kubectl get tracingpolicies -A` returned 0). Kernel tracing for `open` and `write` syscalls is not yet active.

### 3.3 Namespaces Overview
- **Existing:**
  - `kube-system`: Core cluster services, Cilium, Tetragon.
  - `cilium-monitoring`: Prometheus (`prometheus-7cc8784659-4tl2x`) and Grafana (`grafana-65d4578dc4-c8d8r`).
  - `intro`: Cilium practice workload (`deathstar`, `tiefighter`, `xwing`).
  - `default`, `kube-public`, `kube-node-lease`, `cilium-secrets`.
- **Missing:**
  - `ztre-system`: Dedicated namespace for ZTRE agent and RBAC.
  - `ztre-test`: Dedicated namespace for vulnerable test workloads.

### 3.4 Bastion Tooling & Environment
- **Installed Tools:**
  - `kubectl` (`/usr/local/bin/kubectl`) — full cluster-admin access.
  - `helm` (`/usr/local/bin/helm` v3.21.4).
  - `cilium` CLI (`/usr/local/bin/cilium`).
  - `python3` (`/usr/bin/python3` v3.12.3).
  - `sudo` access available (password: `bastion`).
- **Missing Tools on Bastion:**
  - `docker` or `podman` (needed to build container images for the ZTRE agent).
  - `tetra` CLI (can be downloaded to bastion for easy direct query of Tetragon events).

---

## 4. Stage 1 Gap Analysis Matrix

| Roadmap Step | Task | Expected State | Current State | Status |
|---|---|---|---|---|
| **1.1** | Cluster provisioning | 1 CP + 2 Workers | 1 CP + 1 Worker | ✅ **Approved for Dev** |
| **1.1** | Cluster health verification | `kubectl cluster-info` OK | `https://10.91.128.9:6443` | ✅ **Passed** |
| **1.1** | Create `ztre-system` namespace | Namespace exists | Not found | ❌ **Missing** |
| **1.1** | Create `ztre-test` namespace | Namespace exists | Not found | ❌ **Missing** |
| **1.2** | Tetragon installation | Helm chart running | v1.7.1 running on both nodes | ✅ **Passed** |
| **1.2** | TracingPolicy for `open`, `write`, `execve` | Applied in cluster | 0 policies found | ❌ **Missing** |
| **1.2** | Verify event JSON structure | Contains binary, pid, parent, pod info | Verified via live probe test | ✅ **Passed** |
| **1.3** | Cilium `kubeProxyReplacement` | `strict` | `false` | ⚠️ **Needs Update** |
| **1.3** | Cilium healthy status | All nodes OK | All nodes OK | ✅ **Passed** |
| **1.3** | Deploy `ztre-quarantine-policy` | Ingress/egress blocked on label | Not found | ❌ **Missing** |
| **1.3** | Verify quarantine isolation | Traffic blocked when labeled | Not tested | ❌ **Missing** |
| **1.4** | ZTRE Python scaffolding | Full directory structure | Only documentation exists | ❌ **Missing** |
| **1.4** | Dependencies & configs | `pyproject.toml`, policies | Not created | ❌ **Missing** |
| **1.4** | Docker packaging | `Dockerfile` ready | Not created | ❌ **Missing** |
| **1.5** | RBAC ServiceAccount & Role | `patch pods` only | Not created | ❌ **Missing** |

---

## 5. Architectural Flow & Mental Model

```
       [ Attacker / Workload Pod ] (in namespace ztre-test)
                    │
                    │ 1. Malicious execution (e.g. nginx spawns bash)
                    ▼
          [ Linux Kernel (eBPF) ]
                    │
                    │ 2. Tetragon intercepts execve syscall
                    ▼
              [ Tetragon ] (DaemonSet)
                    │
                    │ 3. Streams JSON event via gRPC (/var/run/tetragon/tetragon.sock)
                    ▼
             [ ZTRE Python Agent ] (DaemonSet in ztre-system)
                    │
                    │ 4. Validates process lineage (nginx -> bash is ANOMALOUS)
                    │ 5. Calculates Risk Score (e.g. 75 / Red Zone)
                    │ 6. Decision Engine: Trigger AUTO_CONTAINMENT
                    │ 7. Calls K8s API: kubectl patch pod <name> -p 'labels: {"ztre/quarantine": "true"}'
                    ▼
         [ Kubernetes API Server ]
                    │
                    │ 8. Updates Pod metadata with label ztre/quarantine=true
                    ▼
             [ Cilium CNI (eBPF) ]
                    │
                    │ 9. Matches ztre-quarantine-policy
                    │    Instantly drops all ingress & egress network packets at eBPF layer
                    ▼
     [ Pod Isolated — Zero Network Traffic, Process Intact for Forensics ]
```

