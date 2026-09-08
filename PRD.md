# Product Requirements Document (PRD)

## Zero-Trust Response Engine (ZTRE)
### Autonomous AI Security Agent for Cloud-Native Kubernetes Environments

---

| Field | Details |
|---|---|
| **Document Version** | 1.0.0 |
| **Status** | Draft |
| **Date** | 2026-09-08 |
| **Product Name** | Zero-Trust Response Engine (ZTRE) |
| **Product Type** | Autonomous AI Security Agent / Context-Aware Threat Validation Engine |
| **Target Environment** | Cloud-Native / Kubernetes |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement & Background](#2-problem-statement--background)
3. [Product Vision & Objectives](#3-product-vision--objectives)
4. [Stakeholders](#4-stakeholders)
5. [Functional Requirements](#5-functional-requirements)
6. [System Architecture](#6-system-architecture)
7. [Non-Functional Requirements](#7-non-functional-requirements)
8. [Success Metrics & Evaluation](#8-success-metrics--evaluation)
9. [Out of Scope](#9-out-of-scope)
10. [Glossary](#10-glossary)

---

## 1. Introduction

ZTRE is an autonomous AI security agent that acts as a **Policy Decision Point (PDP)** within a Zero Trust security architecture. It bridges the gap between runtime kernel-level threat observation (Tetragon eBPF) and network-level enforcement (Cilium CNI) to provide intelligent, non-destructive, and automated incident response in Kubernetes environments.

This document specifies the complete functional and non-functional requirements for the ZTRE software system.

---

## 2. Problem Statement & Background

### 2.1 Context

Modern cloud-native infrastructures built on Kubernetes expose complex attack surfaces. Microservice architectures create many lateral paths for an attacker to pivot between services once initial access is obtained. Threats such as **Remote Code Execution (RCE)**, **privilege escalation**, and **lateral movement** are increasingly common in these environments.

### 2.2 Limitations of Existing Solutions

Current runtime security agents (e.g., standard eBPF-based watchdogs) typically respond to detected anomalies using a **destructive, reactive mitigation** strategy:

| Problem | Description |
|---|---|
| **`SIGKILL`-based response** | The default action is to terminate the offending process immediately, destroying all in-memory volatile artifacts |
| **No network revocation** | Terminating a process does not automatically revoke the compromised workload's network access |
| **Kubernetes restart loops** | Killing a managed container triggers the Kubernetes ReplicaSet controller to restart it, potentially causing an *infinite restart loop* |
| **Forensic data loss** | Volatile memory containing attacker tooling, credentials, and command history is irrecoverably lost upon process kill |

### 2.3 Problem Statement

> **How can a security agent autonomously contain an active threat in a Kubernetes cluster — blocking lateral movement at the network layer — without killing the compromised workload's process, thereby preserving forensic artifacts and maintaining service availability?**

---

## 3. Product Vision & Objectives

### 3.1 Vision

ZTRE acts as an intelligent intermediary between the **observation layer** (Tetragon) and the **enforcement layer** (Cilium), autonomously making containment decisions that are proportional, context-aware, and forensics-preserving.

### 3.2 Objectives

| # | Objective | Description |
|---|---|---|
| **O1** | **Context-Aware Threat Validation** | Validate threats dynamically by analyzing process lineage (parent-child execution relationships), not just isolated syscall events, to reduce false positives |
| **O2** | **Multidimensional Risk Assessment** | Calculate a composite risk score across three dimensions: technical severity, execution context, and asset criticality |
| **O3** | **Autonomous Network Containment** | Execute network quarantine of the compromised workload instantly, without sending a termination signal (`SIGKILL`), preserving in-memory forensic artifacts |

---

## 4. Stakeholders

| Role | Concern |
|---|---|
| **Security Operations (SecOps)** | Reduced mean-time-to-contain (MTTC), fewer false positives, automated alerting |
| **Platform / SRE Teams** | Zero application downtime during containment, low computational overhead |
| **Incident Response (IR) / Forensics** | Preservation of volatile memory artifacts for post-incident investigation |
| **Compliance / Audit** | Tamper-proof event logs, audit trail for every automated action |

---

## 5. Functional Requirements

### FR-01 — Event Interception & Telemetry Ingestion

**Description:** ZTRE MUST have an `EventCollector` module that continuously ingests kernel-level telemetry events from Tetragon eBPF probes in real-time.

**Inputs:**
- Tetragon JSON event stream (gRPC / Unix socket)
- Event types: process execution (`execve`), file access (`open`, `write`), network connections, capability changes

**Behavior:**
- Buffer incoming events and parse structured fields: `process.pid`, `process.binary`, `parent.binary`, `namespace`, `pod_name`
- Pass parsed events to the validation pipeline (FR-02)

**Acceptance Criteria:**
- [ ] Agent ingests events with end-to-end latency < 500ms from kernel event to pipeline entry
- [ ] Handles burst events of up to 10,000 events/second without dropping
- [ ] Gracefully reconnects to Tetragon on stream interruption

---

### FR-02 — Context-Aware Threat Validation (Process Lineage Analysis)

**Description:** ZTRE MUST evaluate each event against a **Static Process Lineage Whitelist** to determine if the observed parent→child execution relationship is expected or anomalous.

**Mechanism:**

The agent uses a **deterministic rule-based engine** backed by a static mapping database:

```yaml
# Example: process_lineage_whitelist.yaml
whitelisted_lineages:
  - parent: nginx
    allowed_children: [nginx, sh]  # NOT bash, curl, python
  - parent: java
    allowed_children: [java]
  - parent: postgres
    allowed_children: [postgres]
```

**Classification Output:**

| Status | Description |
|---|---|
| `NORMAL` | Parent-child relationship exists in whitelist; no action |
| `SUSPICIOUS` | Relationship is unusual but not definitively malicious; escalate to risk scoring |
| `ANOMALOUS` | Relationship is a known-bad pattern (e.g., `nginx → bash`); trigger risk scoring with high baseline |

**Acceptance Criteria:**
- [ ] Classification latency < 10ms per event
- [ ] Whitelist is hot-reloadable without agent restart
- [ ] `NORMAL` events are logged only (not forwarded to risk engine)

---

### FR-03 — Dynamic Risk Assessment Engine

**Description:** For all `SUSPICIOUS` or `ANOMALOUS` events, ZTRE MUST calculate a composite **Risk Score** using three weighted dimensions.

**Risk Score Formula:**

```
Risk Score = S + C + A
```

| Dimension | Variable | Weight | Description |
|---|---|---|---|
| **Severity** | `S` | 50% | Technical danger level of the observed syscall or binary (e.g., `chmod u+s` = high; `ls` = low) |
| **Context** | `C` | 30% | Degree of process lineage anomaly (`NORMAL`=0, `SUSPICIOUS`=15, `ANOMALOUS`=30) |
| **Asset Criticality** | `A` | 20% | Criticality tier of the targeted workload namespace/identity |

**Asset Criticality Tiers:**

| Tier | Examples | Score |
|---|---|---|
| Critical | Database, Secrets Manager, Auth Service | 20 |
| High | Internal API, Message Queue | 15 |
| Medium | Backend Services | 10 |
| Low | Frontend, Static servers | 5 |

**Acceptance Criteria:**
- [ ] Score is calculated and attached to each event within 5ms
- [ ] Score configuration (weights, tiers) is externally configurable via a YAML/JSON policy file
- [ ] All score calculations are logged with their input parameters for audit

---

### FR-04 — Decision Engine & Tiered Response

**Description:** ZTRE MUST evaluate the computed Risk Score against a **tiered response matrix** and execute the corresponding action.

**Response Matrix:**

| Risk Zone | Score Range | Action | Description |
|---|---|---|---|
| 🟢 **Green** | `< 40` | `ALLOW & LOG` | Record event for visibility; no action taken |
| 🟡 **Yellow** | `40 – 69` | `LOG & ALERT` | Emit a high-severity security alert to the configured alerting channel (PagerDuty, Slack, SIEM); flag for manual review |
| 🔴 **Red** | `≥ 70` | `AUTO CONTAINMENT` | Immediately trigger autonomous network quarantine (FR-05) |

**Acceptance Criteria:**
- [ ] Decision is made within 20ms of receiving the risk score
- [ ] Threshold values are externally configurable without code changes
- [ ] All decisions (ALLOW, ALERT, CONTAIN) are written to an immutable audit log

---

### FR-05 — Automated Network Containment

**Description:** For events scoring `≥ 70` (Red Zone), ZTRE MUST autonomously quarantine the compromised Pod by patching its labels via the Kubernetes API, triggering Cilium's network policy enforcement — **without sending `SIGKILL` to any process**.

**Containment Flow:**

```
[ZTRE Decision Engine]
        │
        │  PATCH /api/v1/namespaces/{ns}/pods/{pod-name}
        │  Body: { "metadata": { "labels": { "ztre/quarantine": "true" } } }
        ▼
[Kubernetes API Server]
        │
        │  Label updated on Pod object
        ▼
[Cilium Network Policy (CiliumNetworkPolicy)]
        │  Selector: matchLabels: { ztre/quarantine: "true" }
        │  Ingress: Deny All / Egress: Deny All
        ▼
[eBPF Data Plane]
   DROP all ingress & egress traffic to/from the quarantined Pod
```

**Pre-requisite — CiliumNetworkPolicy:**

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: ztre-quarantine-policy
spec:
  endpointSelector:
    matchLabels:
      ztre/quarantine: "true"
  ingress: []   # Deny all ingress
  egress: []    # Deny all egress
```

**Acceptance Criteria:**
- [ ] Pod label patch is applied within 1 second of the RED zone decision
- [ ] Cilium network policy is enforced at the eBPF data plane within 3 seconds of label application
- [ ] The target container process is **NOT** killed; only network access is revoked
- [ ] Containment action is recorded in the audit log with timestamp, pod name, namespace, and risk score
- [ ] ZTRE MUST handle Kubernetes API errors gracefully (retry with exponential backoff, max 3 retries)

---

## 6. System Architecture

### 6.1 Overview

ZTRE is deployed as a **user-space Python agent** running as a privileged `DaemonSet` on each Kubernetes Worker Node. It sits between the kernel-space eBPF layers and the Kubernetes control plane.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                            │
│                                                                      │
│  ┌───────────────────────────────┐                                   │
│  │       Control Plane           │                                   │
│  │   ┌───────────────────────┐   │                                   │
│  │   │  Kubernetes API Server│◄──┼──── PATCH (label quarantine)      │
│  │   └───────────────────────┘   │                                   │
│  └───────────────────────────────┘                                   │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                        Worker Node                            │   │
│  │                                                               │   │
│  │  ┌─────────────── User Space ──────────────────────────────┐  │   │
│  │  │                                                         │  │   │
│  │  │   ┌─────────────────────────────────────────────────┐   │  │   │
│  │  │   │              ZTRE Agent (Python)                │   │  │   │
│  │  │   │  ┌──────────────┐  ┌────────────┐  ┌────────┐  │   │  │   │
│  │  │   │  │EventCollector│→ │ Validation │→ │Decision│  │   │  │   │
│  │  │   │  │  (FR-01)     │  │  (FR-02)   │  │(FR-04) │  │   │  │   │
│  │  │   │  └──────────────┘  └────────────┘  └────┬───┘  │   │  │   │
│  │  │   │                   ┌─────────────┐        │      │   │  │   │
│  │  │   │                   │Risk Engine  │←───────┘      │   │  │   │
│  │  │   │                   │  (FR-03)    │               │   │  │   │
│  │  │   │                   └─────────────┘               │   │  │   │
│  │  │   └─────────────────────────────────────────────────┘   │  │   │
│  │  │                                                         │  │   │
│  │  │   ┌──────────────────────────────────────────────────┐  │  │   │
│  │  │   │          Protected Workloads (Pods)               │  │  │   │
│  │  │   └──────────────────────────────────────────────────┘  │  │   │
│  │  └─────────────────────────────────────────────────────────┘  │   │
│  │                                                               │   │
│  │  ┌─────────────── Kernel Space ───────────────────────────┐   │   │
│  │  │   ┌────────────────────┐   ┌────────────────────────┐  │   │   │
│  │  │   │  Tetragon eBPF     │   │  Cilium eBPF Network   │  │   │   │
│  │  │   │  Probes (Observer) │   │  Datapath (Enforcer)   │  │   │   │
│  │  │   └────────────────────┘   └────────────────────────┘  │   │   │
│  │  └────────────────────────────────────────────────────────┘   │   │
│  └───────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.2 Component Responsibilities

| Component | Layer | Responsibility |
|---|---|---|
| **Tetragon eBPF Probes** | Kernel Space | Observe syscalls, process exec, file access; emit structured JSON events |
| **Cilium eBPF Datapath** | Kernel Space | Enforce network policies at the eBPF data plane; drop/allow traffic based on pod labels |
| **ZTRE Agent** | User Space | Ingest events, validate, score, decide, and execute containment via K8s API |
| **Kubernetes API Server** | Control Plane | Accept label patch requests; propagate metadata changes to nodes |

### 6.3 Event Data Flow

```
Tetragon Probe
    │  (JSON event stream)
    ▼
EventCollector (FR-01)
    │  (parsed Event object)
    ▼
Lineage Validator (FR-02)
    │  (Classification: NORMAL / SUSPICIOUS / ANOMALOUS)
    ├──[NORMAL]──► Audit Log (no further action)
    │
    ▼
Risk Engine (FR-03)
    │  (Risk Score: 0–100)
    ▼
Decision Engine (FR-04)
    ├──[Score < 40]────► Log only
    ├──[40 ≤ Score < 70]► Alert (PagerDuty / Slack / SIEM)
    └──[Score ≥ 70]────► Containment Executor (FR-05)
                                │
                                ▼
                        Kubernetes API (PATCH pod label)
                                │
                                ▼
                        Cilium enforces deny-all at eBPF layer
```

---

## 7. Non-Functional Requirements

### 7.1 Non-Destructive Mitigation (NFR-01)

- The agent MUST NOT send `SIGKILL`, `SIGTERM`, or any termination signal to application processes
- Containment is achieved exclusively through network isolation at the eBPF layer
- In-memory volatile artifacts (process memory, open file descriptors, network sockets) MUST remain accessible post-containment for forensic collection

### 7.2 Service Availability — Zero-Downtime Containment (NFR-02)

- When a Pod is quarantined, the Kubernetes Service endpoint controller MUST automatically remove the quarantined Pod from the load balancer's endpoint slice
- The ReplicaSet controller MUST automatically provision a new healthy Pod replica
- Legitimate traffic MUST be seamlessly routed to healthy replicas with no user-facing downtime

### 7.3 Performance & Low Overhead (NFR-03)

| Metric | Requirement |
|---|---|
| Agent CPU usage | ≤ 2% of a single CPU core under normal load |
| Agent memory footprint | ≤ 128 MB RSS |
| Event pipeline throughput | ≥ 10,000 events/second without dropping |
| End-to-end containment latency | ≤ 5 seconds from kernel event to Cilium enforcement |

### 7.4 Security (NFR-04)

- ZTRE agent runs with the minimum required RBAC permissions (only `patch` on `pods` resource)
- All communication with the Kubernetes API Server MUST use mTLS
- The process lineage whitelist and risk scoring policy files MUST NOT be modifiable by the workloads ZTRE is monitoring

### 7.5 Reliability & Resilience (NFR-05)

- Agent MUST survive Tetragon stream restarts and reconnect automatically
- Kubernetes API patch failures MUST trigger a retry with exponential backoff (max 3 retries, initial delay 100ms)
- Agent crash MUST be handled by its own Pod's `restartPolicy: Always` without loss of in-flight decisions

### 7.6 Observability (NFR-06)

- All agent decisions MUST be emitted as structured JSON log events
- Agent MUST expose a Prometheus `/metrics` endpoint with the following counters:
  - `ztre_events_ingested_total`
  - `ztre_events_classified_total{status="normal|suspicious|anomalous"}`
  - `ztre_containment_actions_total`
  - `ztre_api_errors_total`
- Audit logs MUST be immutable and forwarded to an external SIEM or log aggregator

---

## 8. Success Metrics & Evaluation

ZTRE will be evaluated against threat simulation scenarios aligned with the **MITRE ATT&CK** framework (e.g., `T1059` - Command and Scripting Interpreter, `T1021` - Lateral Movement).

| # | Metric | Description | Target |
|---|---|---|---|
| **M1** | **Detection Accuracy** | Percentage of true threat events (RCE, Reverse Shell) correctly identified | ≥ 95% |
| **M2** | **False Positive Rate** | Percentage of legitimate application activity incorrectly flagged as a threat | ≤ 2% |
| **M3** | **Policy Enforcement Latency** | Time from kernel-level event detection to active Cilium network block | ≤ 5 seconds (P99) |
| **M4** | **Containment Success Rate** | Percentage of incidents where lateral movement was blocked without triggering a Kubernetes restart loop | ≥ 99% |
| **M5** | **Computational Overhead** | Average CPU and RAM consumption of the ZTRE agent process in production | CPU ≤ 2%, RAM ≤ 128 MB |

---

## 9. Out of Scope

The following are explicitly **not** in scope for ZTRE v1.0:

- **Machine Learning-based anomaly detection** — The initial version uses deterministic, rule-based validation only
- **Windows or non-Linux node support** — eBPF requires Linux kernel ≥ 5.4
- **Automatic Pod deletion or workload remediation** — ZTRE only applies network isolation, not lifecycle management
- **Vulnerability scanning or SAST/DAST integration** — ZTRE is a runtime agent only
- **Multi-cluster federation** — V1 targets a single Kubernetes cluster

---

## 10. Glossary

| Term | Definition |
|---|---|
| **eBPF** | Extended Berkeley Packet Filter — a kernel technology for running sandboxed programs in the OS kernel |
| **Tetragon** | A Cilium project providing eBPF-based runtime security observability and enforcement |
| **Cilium** | A CNI plugin using eBPF for high-performance, policy-driven Kubernetes networking |
| **CNI** | Container Network Interface — the standard plugin interface for Kubernetes networking |
| **PDP** | Policy Decision Point — the component that evaluates a request against policy and issues a decision |
| **PEP** | Policy Enforcement Point — the component that enforces decisions made by the PDP |
| **Process Lineage** | The parent-child chain of process execution (e.g., `systemd → nginx → bash`) |
| **Lateral Movement** | An attacker technique of pivoting from a compromised host/pod to other systems in the network |
| **RCE** | Remote Code Execution — a class of vulnerability allowing attackers to run arbitrary code |
| **Volatile Artifacts** | Ephemeral data existing only in RAM (open sockets, bash history, decrypted credentials) that is lost when a process is killed |
| **MTTC** | Mean Time to Contain — the average time from threat detection to successful containment |
| **RBAC** | Role-Based Access Control — Kubernetes mechanism for controlling API access |
| **mTLS** | Mutual TLS — a protocol where both client and server authenticate each other |
| **SIEM** | Security Information and Event Management — a platform for aggregating and analyzing security logs |

---

*This document defines the software specification for ZTRE v1.0. It is intended for engineering, security, and product stakeholders.*
