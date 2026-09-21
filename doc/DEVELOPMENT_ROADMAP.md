# ZTRE Development Roadmap

## Step-by-Step Implementation Plan

---

| Field | Details |
|---|---|
| **Document Version** | 1.0.0 |
| **Date** | 2026-09-08 |
| **Based On** | [PRD.md](./PRD.md) v1.0.0 |
| **Total Stages** | 7 (including Stage 2.5) |
| **Total Steps** | 34 |

---

## Overview

This document breaks the ZTRE development into **7 sequential stages**, each with concrete steps, deliverables, acceptance gates, and PRD traceability. Stages are ordered by dependency — each stage builds on the outputs of the previous one.

```
Stage 1          Stage 2          Stage 2.5           Stage 3          Stage 4          Stage 5          Stage 6
───────          ───────          ─────────           ───────          ───────          ───────          ───────
Foundation  ──►  Event        ──►  Behavioral     ──►  Validation  ──►  Decision &   ──►  Integration  ──►  Hardening
& Infra          Pipeline         Discovery &         & Scoring        Containment      Testing          & Release
                                  Baseline Learning

 Weeks 1–2        Weeks 3–4        Weeks 5–6           Weeks 7–8        Weeks 9–10       Weeks 11–12      Weeks 13–14
```

> **Architectural Decision (v1.1.0):** Stage 2.5 was introduced to establish a data-driven behavioral baseline before validation and risk scoring. Without observing real workload behavior, the process lineage whitelist would be a manually-crafted guess — leading to excessive false positives and an incomplete security posture. Stage 2.5 ensures the whitelist used by Stage 3 is empirically grounded in observed cluster behavior.

---

## Stage 1 — Foundation & Infrastructure Setup

> **Goal:** Stand up the development environment, Kubernetes cluster, and all external dependencies so that the ZTRE agent has a working platform to develop against.

**Duration:** Weeks 1–2
**PRD References:** §6 System Architecture, NFR-04 (Security), NFR-06 (Observability)

### Step 1.1 — Kubernetes Cluster Provisioning

| Item | Details |
|---|---|
| **Action** | Provision a development Kubernetes cluster (minikube, kind, or managed K8s) with minimum 1 control-plane + 1 worker nodes |
| **Deliverable** | Working `kubeconfig` with cluster-admin access |
| **Tools** | `kind` / `minikube` / `kubeadm` |

**Tasks:**
- [ ] Create cluster configuration manifest with 1 worker nodes
- [ ] Verify `kubectl cluster-info` returns healthy status
- [ ] Create dedicated `ztre-system` namespace for agent deployment
- [ ] Create dedicated `ztre-test` namespace for vulnerable test workloads

### Step 1.2 — Tetragon eBPF Installation & Verification

| Item | Details |
|---|---|
| **Action** | Deploy Tetragon via Helm into the cluster and verify kernel-level event generation |
| **Deliverable** | Tetragon DaemonSet running on all worker nodes, emitting JSON events |
| **Dependency** | Step 1.1 |

**Tasks:**
- [ ] `helm install tetragon cilium/tetragon -n kube-system`
- [ ] Deploy a TracingPolicy for `execve`, `open`, `write` syscalls
- [ ] Verify events via `kubectl exec -n kube-system ds/tetragon -- tetra getevents`
- [ ] Confirm JSON event structure contains: `process.binary`, `process.pid`, `parent.binary`, `process.pod.namespace`, `process.pod.name`

### Step 1.3 — Cilium CNI Installation & Network Policy Verification

| Item | Details |
|---|---|
| **Action** | Install Cilium as the cluster CNI and deploy the ZTRE quarantine CiliumNetworkPolicy |
| **Deliverable** | Cilium running, quarantine policy pre-deployed and verified |
| **Dependency** | Step 1.1 |

**Tasks:**
- [ ] Install Cilium via Helm with `--set kubeProxyReplacement=strict`
- [ ] Verify `cilium status` reports all nodes healthy
- [ ] Deploy `ztre-quarantine-policy` CiliumClusterwideNetworkPolicy:
  ```yaml
  apiVersion: "cilium.io/v2"
  kind: CiliumClusterwideNetworkPolicy
  metadata:
    name: ztre-quarantine-policy
  spec:
    endpointSelector:
      matchLabels:
        ztre/quarantine: "true"
    ingressDeny:
    - fromEntities:
      - all
    egressDeny:
    - toEntities:
      - all
  ```
- [ ] Manual test: label a test pod with `ztre/quarantine=true`, confirm all traffic is blocked
- [ ] Manual test: remove the label, confirm traffic resumes

### Step 1.4 — ZTRE Go Project Scaffolding

| Item | Details |
|---|---|
| **Action** | Initialize the ZTRE Go project with package structure, module management (`go.mod`), and CI skeleton |
| **Deliverable** | Repository with runnable Go skeleton, linting, and test harness |

**Tasks:**
- [ ] Initialize project structure:
  ```
  ztre/
  ├── cmd/
  │   └── ztre-agent/
  │       └── main.go              # Entrypoint
  ├── pkg/
  │   ├── collector/               # FR-01 (Tetragon gRPC client)
  │   ├── validator/               # FR-02 (Lineage validator)
  │   ├── risk/                    # FR-03 (Risk scoring engine)
  │   ├── decision/                # FR-04 (Decision engine)
  │   ├── containment/             # FR-05 (K8s pod patcher)
  │   ├── config/                  # YAML policy loader
  │   └── observability/           # Logging & Prometheus metrics
  ├── config/
  │   ├── process_lineage_whitelist.yaml
  │   ├── risk_scoring_policy.yaml
  │   └── agent_config.yaml
  ├── tests/
  ├── deploy/
  │   ├── Dockerfile
  │   ├── daemonset.yaml
  │   └── rbac.yaml
  ├── go.mod
  ├── go.sum
  └── README.md
  ```
- [ ] Set up `go.mod` with dependencies: `github.com/cilium/tetragon/api/v1/tetragon`, `k8s.io/client-go`, `gopkg.in/yaml.v3`, `github.com/prometheus/client_golang`, `go.uber.org/zap`
- [ ] Configure `go test`, `golangci-lint`
- [ ] Write a minimal `main.go` that starts and logs "ZTRE Agent started"
- [ ] Create multi-stage `Dockerfile` (`golang:1.22-alpine` builder -> `gcr.io/distroless/static:nonroot`)

### Step 1.5 — RBAC & Service Account Configuration

| Item | Details |
|---|---|
| **Action** | Create the minimum-privilege Kubernetes RBAC resources for the ZTRE agent |
| **Deliverable** | ServiceAccount + ClusterRole + ClusterRoleBinding YAML applied to cluster |
| **PRD Reference** | NFR-04 (Security — minimum RBAC) |

**Tasks:**
- [ ] Create `ServiceAccount` named `ztre-agent` in `ztre-system` namespace
- [ ] Create `ClusterRole` with **only** `patch` verb on `pods` resource
- [ ] Create `ClusterRoleBinding` binding the role to the service account
- [ ] Verify: the SA can `kubectl patch pod` but **cannot** `delete`, `create`, or `exec`

---

### 🚪 Stage 1 Gate

| Criteria | Verified |
|---|---|
| K8s cluster running with 1 worker node | ☐ |
| Tetragon emitting JSON events from kernel probes | ☐ |
| Cilium installed; quarantine policy blocks traffic when label applied | ☐ |
| Go project skeleton builds and runs in Docker | ☐ |
| RBAC restricts agent to `patch pods` only | ☐ |

---

## Stage 2 — Event Pipeline (FR-01)

> **Goal:** Build the `EventCollector` module that ingests, parses, and buffers Tetragon events in real-time.

**Duration:** Weeks 3–4
**PRD References:** FR-01, NFR-03 (Performance), NFR-05 (Reliability)

### Step 2.1 — Tetragon gRPC Client

| Item | Details |
|---|---|
| **Action** | Implement a gRPC client using official Tetragon Go SDK that connects to the Tetragon unix domain socket (`/var/run/tetragon/tetragon.sock`) |
| **Deliverable** | `TetragonClient` struct with streaming capability via `tetragon.FineGuidanceSensorsClient` |

**Tasks:**
- [ ] Import official Tetragon client SDK (`github.com/cilium/tetragon/api/v1/tetragon`)
- [ ] Implement `TetragonClient` connecting over `unix:///var/run/tetragon/tetragon.sock` using `GetEvents(ctx, &tetragon.GetEventsRequest{})`
- [ ] Handle connection lifecycle: connect, reconnect on failure with exponential backoff
- [ ] Unit test: mock gRPC server → client receives events

### Step 2.2 — Event Parser & Data Model

| Item | Details |
|---|---|
| **Action** | Define the internal `SecurityEvent` data model in Go and build a parser that extracts structured fields from `*tetragon.GetEventsResponse` |
| **Deliverable** | `SecurityEvent` struct, `EventParser` interface and implementation |

**Tasks:**
- [ ] Define `SecurityEvent` struct:
  ```go
  type SecurityEvent struct {
      Timestamp    time.Time
      EventType    string    // execve, file_access, network
      PID          uint32
      Binary       string    // e.g., "bash"
      ParentBinary string    // e.g., "nginx"
      Namespace    string
      PodName      string
      RawResponse  *tetragon.GetEventsResponse
  }
  ```
- [ ] Implement `EventParser.Parse(res *tetragon.GetEventsResponse) (*SecurityEvent, error)`
- [ ] Handle unhandled or filtered events gracefully (return nil/skip)
- [ ] Unit tests with real Tetragon event samples (captured from Step 1.2)

### Step 2.3 — Event Buffer & Throughput Handling

| Item | Details |
|---|---|
| **Action** | Add a buffered Go channel between the collector and downstream pipeline to absorb event bursts |
| **Deliverable** | Bounded channel `chan *SecurityEvent` with configurable buffer size and overflow strategy |
| **PRD Reference** | FR-01 acceptance: 10,000 events/sec without dropping |

**Tasks:**
- [ ] Implement bounded Go channel buffer (default capacity: 50,000)
- [ ] Overflow strategy: non-blocking select drop, log warning + increment `ztre_events_dropped_total` metric
- [ ] Worker goroutine pool pulling from channel and forwarding to validation pipeline
- [ ] Load test: synthetic event generator → verify 10k events/sec throughput
- [ ] Benchmark end-to-end latency: target < 500ms

### Step 2.4 — Observability for Event Pipeline

| Item | Details |
|---|---|
| **Action** | Add structured logging (Zap / slog) and Prometheus metrics for the event ingestion layer |
| **Deliverable** | Structured logger, Prometheus counter `ztre_events_ingested_total` |
| **PRD Reference** | NFR-06 |

**Tasks:**
- [ ] Configure `zap` logger with JSON encoder, timestamp, log level
- [ ] Register Prometheus counter: `ztre_events_ingested_total`
- [ ] Register Prometheus histogram: `ztre_event_parse_duration_seconds`
- [ ] Expose `/metrics` HTTP endpoint on port 9090 using `promhttp.Handler()`
- [ ] Integration test: ingest events → verify metrics increment

---

### 🚪 Stage 2 Gate

| Criteria | Verified |
|---|---|
| Agent connects to Tetragon gRPC stream and receives events | ☐ |
| Events are parsed into `SecurityEvent` struct | ☐ |
| Pipeline handles 10,000 events/sec without dropping | ☐ |
| Auto-reconnect works when Tetragon restarts | ☐ |
| `/metrics` endpoint exposes `ztre_events_ingested_total` | ☐ |

---

## Stage 2.5 — Behavioral Discovery & Baseline Learning

> **Goal:** Observe real-world execution patterns passively, build an empirical behavioral baseline, auto-generate a data-driven process lineage whitelist, and provide a shadow validation mode — all before enabling enforcement.

**Duration:** Weeks 5–6
**PRD References:** FR-02 (Context-Aware Threat Validation — data foundation), O1 (Context-Aware Threat Validation)
**Rationale:** Every Kubernetes cluster has unique workloads. A hand-crafted whitelist will be incomplete on day one, generating massive false positives. Discovery ensures the whitelist is empirically grounded in observed cluster behavior.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  DISCOVERY ENGINE (pkg/discovery/)                              │
│                                                                 │
│  EventBuffer ──► BehaviorTracker ──► BaselineStore              │
│                                                                 │
│  • Accumulates parent→child execution pairs                     │
│  • Counts frequency per (namespace, workload, parent, child)    │
│  • Tracks first-seen / last-seen timestamps                     │
│  • Records execution context (time-of-day, node, container)     │
│  • NO blocking, NO alerting — pure observation                  │
│                                                                 │
│  Output: baseline_report.json + auto_whitelist.yaml             │
└─────────────────────────────────────────────────────────────────┘
```

### Step 2.5.1 — Discovery Data Model

| Item | Details |
|---|---|
| **Action** | Define data structures for tracking observed execution patterns and workload behavioral profiles |
| **Deliverable** | `pkg/discovery/types.go` with `ExecutionPattern`, `LineageProfile`, `BaselineSnapshot`, `PatternStats` structs |

**Tasks:**
- [ ] Define `ExecutionPattern` struct:
  ```go
  type ExecutionPattern struct {
      ParentBinary  string    `json:"parent_binary"`
      ChildBinary   string    `json:"child_binary"`
      Namespace     string    `json:"namespace"`
      WorkloadName  string    `json:"workload_name"`
      Count         uint64    `json:"count"`          // how many times observed
      FirstSeen     time.Time `json:"first_seen"`
      LastSeen      time.Time `json:"last_seen"`
      Nodes         []string  `json:"nodes"`          // which nodes
  }
  ```
- [ ] Define `LineageProfile` struct (aggregated baseline per workload):
  ```go
  type LineageProfile struct {
      Namespace       string              `json:"namespace"`
      WorkloadName    string              `json:"workload_name"`
      WorkloadKind    string              `json:"workload_kind"`
      Patterns        []ExecutionPattern  `json:"patterns"`
      TotalEvents     uint64              `json:"total_events"`
      UniqueProcesses int                 `json:"unique_processes"`
      StableAfter     time.Time           `json:"stable_after"`
  }
  ```
- [ ] Define `PatternStats` struct for statistical analysis:
  ```go
  type PatternStats struct {
      Frequency     float64 // events per hour
      IsBurst       bool    // only appears in short bursts
      IsRecurring   bool    // appears consistently across time windows
      IsCrossNode   bool    // appears on multiple nodes (expected for DaemonSets)
      Percentile    float64 // where this pattern falls in frequency distribution
      ZScore        float64 // standard deviations from mean frequency
  }
  ```
- [ ] Define `BaselineSnapshot` struct for periodic persistence
- [ ] Unit tests for struct serialization/deserialization (JSON round-trip)

### Step 2.5.2 — Behavior Tracker

| Item | Details |
|---|---|
| **Action** | Implement the core tracker that receives `SecurityEvent`s and maintains in-memory frequency maps of observed parent→child execution pairs |
| **Deliverable** | `pkg/discovery/tracker.go` — `BehaviorTracker` struct with `Track(event)` method |
| **Dependency** | Step 2.5.1 |

**Tasks:**
- [ ] Implement `BehaviorTracker` with concurrent-safe map (`sync.RWMutex` or `sync.Map`):
  ```go
  type BehaviorTracker struct {
      mu       sync.RWMutex
      patterns map[string]*ExecutionPattern  // key: "namespace/workload/parent→child"
      profiles map[string]*LineageProfile    // key: "namespace/workload"
      started  time.Time
  }
  ```
- [ ] `Track(event *collector.SecurityEvent)` — updates frequency count, first-seen/last-seen timestamps, node list
- [ ] `GetPatterns() []ExecutionPattern` — returns a snapshot of all observed patterns
- [ ] `GetProfile(namespace, workload string) *LineageProfile` — returns the behavioral profile for a specific workload
- [ ] `GetStats() map[string]*PatternStats` — computes frequency, z-score, burst detection for each pattern
- [ ] Handle edge cases: empty parent binary (init processes), system namespaces (`kube-system`), sidecar containers
- [ ] Add Prometheus metrics:
  - `ztre_discovery_patterns_observed_total` — counter of unique parent→child pairs discovered
  - `ztre_discovery_events_tracked_total` — counter of total events processed in discovery mode
- [ ] Benchmark: tracking overhead < 1μs per event (must not slow down the pipeline)
- [ ] Unit tests:
  - [ ] Track multiple events → verify correct frequency counts
  - [ ] Track events from multiple namespaces → verify separate profiles
  - [ ] Concurrent access from 4 workers → no races (`go test -race`)

### Step 2.5.3 — Baseline Store & Stability Detection

| Item | Details |
|---|---|
| **Action** | Implement persistence for baseline snapshots and automatic stability detection (determines when the baseline has converged) |
| **Deliverable** | `pkg/discovery/baseline.go` — `BaselineStore` struct with snapshot persistence and stability check |
| **Dependency** | Step 2.5.2 |

**Tasks:**
- [ ] Implement `BaselineStore` with periodic snapshot persistence:
  ```go
  type BaselineStore struct {
      tracker         *BehaviorTracker
      snapshotDir     string            // e.g., "data/discovery/"
      snapshotInterval time.Duration    // e.g., 1 hour
      stabilityWindow  time.Duration    // e.g., 4 hours of no new patterns
  }
  ```
- [ ] `SaveSnapshot()` — serializes current patterns to `data/discovery/baseline_YYYYMMDD_HHMMSS.json`
- [ ] `LoadLatestSnapshot()` — loads the most recent snapshot on agent restart (resume learning)
- [ ] `IsStable() bool` — returns `true` if no new unique parent→child pairs have been observed for the configured `stabilityWindow`
- [ ] `GetStabilityStatus() StabilityStatus` — returns `LEARNING`, `STABILIZING`, or `STABLE` with metadata (new patterns in last window, time since last new pattern)
- [ ] Periodic snapshot loop as a goroutine with context cancellation
- [ ] Log stability transitions: `LEARNING → STABILIZING → STABLE`
- [ ] Add Prometheus gauge: `ztre_discovery_stability_status` (0=LEARNING, 1=STABILIZING, 2=STABLE)
- [ ] Unit tests:
  - [ ] Save/load round-trip preserves all pattern data
  - [ ] Stability detection triggers after configured window with no new patterns
  - [ ] New pattern resets stability timer

### Step 2.5.4 — Baseline Reporter & Auto-Whitelist Generation

| Item | Details |
|---|---|
| **Action** | Generate human-readable discovery reports and auto-generate `process_lineage_whitelist.yaml` from observed baseline data |
| **Deliverable** | `pkg/discovery/reporter.go` — `BaselineReporter` struct that outputs `baseline_report.json` and `auto_whitelist.yaml` |
| **Dependency** | Step 2.5.3 |

**Tasks:**
- [ ] Implement `GenerateReport() *BaselineReport` with:
  - Learning window (start/end timestamps)
  - Total events observed
  - Unique lineage pairs discovered
  - Per-workload behavioral profiles
  - Anomaly candidates (patterns with z-score > 2.0 — rare even during learning)
  - Stability status and recommendation
- [ ] Implement `GenerateWhitelist() WhitelistConfig` — converts high-confidence observed patterns into the `process_lineage_whitelist.yaml` format:
  ```yaml
  # AUTO-GENERATED by ZTRE Discovery Engine
  # Learning window: 2026-09-15T00:00Z → 2026-09-18T00:00Z
  # Total events observed: 1,247,832
  
  whitelisted_lineages:
    - parent: nginx
      allowed_children: [nginx, sh]
      confidence: 0.99
      source: auto-discovered
      observed_count: 45000

    - parent: containerd-shim
      allowed_children: [pause, nginx, node, java]
      confidence: 0.99
      source: auto-discovered

    - parent: node
      allowed_children: [node, npm, sh, curl]
      confidence: 0.60
      source: auto-discovered
      review_flag: true            # curl seen only 3 times
      temporal_note: "curl only observed during CI deploys"
  ```
- [ ] Confidence scoring logic:
  - `≥ 100 observations` AND `recurring across multiple time windows` → confidence ≥ 0.95
  - `10–99 observations` AND `recurring` → confidence 0.70–0.94
  - `< 10 observations` OR `burst-only` → confidence < 0.70, `review_flag: true`
- [ ] Write `baseline_report.json` to `data/discovery/`
- [ ] Write `auto_whitelist.yaml` to `config/` (alongside the manual whitelist)
- [ ] CLI trigger: `--generate-report` flag or automatic on stability transition
- [ ] Unit tests:
  - [ ] High-frequency patterns produce high confidence scores
  - [ ] Rare/burst patterns are flagged for review
  - [ ] Generated YAML is valid and parsable by the Stage 3 whitelist loader

### Step 2.5.5 — Agent Mode Router

| Item | Details |
|---|---|
| **Action** | Implement the tri-modal agent operation (Discovery / Shadow / Enforcement) with mode-aware event routing in the worker pool |
| **Deliverable** | Mode router in `cmd/ztre-agent/main.go`, mode configuration in `config/agent_config.yaml` |
| **Dependency** | Steps 2.5.2, 2.5.4 |

**Tasks:**
- [ ] Define agent modes:
  ```go
  type AgentMode string
  const (
      ModeDiscovery   AgentMode = "discovery"    // passive observe, build baseline
      ModeShadow      AgentMode = "shadow"        // classify + score but don't enforce
      ModeEnforcement AgentMode = "enforcement"   // full pipeline with containment
  )
  ```
- [ ] Update `config/agent_config.yaml` with mode and discovery settings:
  ```yaml
  agent:
    mode: "discovery"    # discovery | shadow | enforcement
    discovery:
      learning_window: 72h
      snapshot_interval: 1h
      stability_threshold: 4h
      auto_generate_whitelist: true
      output_dir: "data/discovery"
    shadow:
      use_whitelist: "config/auto_whitelist.yaml"
      log_decisions: true
      enforce: false
    enforcement:
      use_whitelist: "config/process_lineage_whitelist.yaml"
      enforce: true
  ```
- [ ] Modify worker loop in `main.go` to route based on mode:
  ```go
  for event := range eventBuffer.Events() {
      switch agentMode {
      case ModeDiscovery:
          discoveryEngine.Track(event)
      case ModeShadow:
          discoveryEngine.Track(event)  // continue learning
          classification := validator.Classify(event)
          if classification != Normal {
              score := riskEngine.Calculate(event, classification)
              audit.LogShadow(event, classification, score)
          }
      case ModeEnforcement:
          // full Stage 3+4 pipeline
      }
  }
  ```
- [ ] Add `--mode` CLI flag with override capability
- [ ] Log mode transitions and current mode at startup
- [ ] Add Prometheus label: `ztre_agent_mode` gauge
- [ ] Unit tests:
  - [ ] Discovery mode only calls tracker (no validation/scoring)
  - [ ] Shadow mode calls tracker AND validator but does NOT enforce
  - [ ] Enforcement mode calls full pipeline

### Step 2.5.6 — Shadow Mode Integration

| Item | Details |
|---|---|
| **Action** | Implement shadow mode that runs the full validation and risk scoring pipeline but only logs decisions without enforcing containment — a dry-run validation before going to enforcement |
| **Deliverable** | Shadow mode logging with "would-have" decision output |
| **Dependency** | Step 2.5.5, Stage 3 validator (can be implemented in parallel) |

**Tasks:**
- [ ] In shadow mode, run the same classification and scoring logic as enforcement
- [ ] Log shadow decisions with clear `[SHADOW]` prefix:
  ```json
  {
    "timestamp": "2026-09-20T14:30:00Z",
    "mode": "shadow",
    "pod": "nginx-abc123",
    "namespace": "frontend",
    "parent": "nginx",
    "child": "bash",
    "classification": "ANOMALOUS",
    "total_risk_score": 70,
    "would_have_action": "AUTO_CONTAINMENT",
    "enforced": false
  }
  ```
- [ ] Add Prometheus counter: `ztre_shadow_decisions_total{action}` — tracks what would have happened
- [ ] Generate shadow mode summary report: false positive rate estimate, containment rate, alert rate
- [ ] Compare shadow decisions against known-good/known-bad test scenarios to validate whitelist quality before going to enforcement
- [ ] Unit tests:
  - [ ] Shadow mode produces decision logs but does NOT patch pods
  - [ ] Shadow metrics increment correctly

### Step 2.5.7 — Discovery Integration Testing

| Item | Details |
|---|---|
| **Action** | End-to-end integration test: deploy agent in discovery mode on the live cluster, observe real workloads, validate baseline generation |
| **Deliverable** | Verified discovery pipeline producing accurate baseline from live Tetragon events |
| **Dependency** | All Step 2.5.x |

**Tasks:**
- [ ] Deploy ZTRE agent in `discovery` mode to the cluster
- [ ] Run normal workload activity in `ztre-test` namespace for ≥ 1 hour
- [ ] Verify `BehaviorTracker` accumulates correct pattern counts
- [ ] Verify baseline snapshots are persisted to disk
- [ ] Trigger `--generate-report` and verify:
  - [ ] `baseline_report.json` contains all observed lineage pairs
  - [ ] `auto_whitelist.yaml` is valid YAML matching the whitelist schema
  - [ ] High-frequency patterns (e.g., `containerd-shim → pause`) have high confidence
  - [ ] Known-rare patterns are flagged for review
- [ ] Switch to `shadow` mode with the auto-generated whitelist
- [ ] Inject a known attack (e.g., `nginx → bash`) and verify shadow log shows `would_have_action: AUTO_CONTAINMENT`
- [ ] Verify normal operations show `NORMAL` classification (no false positives)
- [ ] Run `go test -race ./pkg/discovery/...` — zero race conditions

---

### 🚪 Stage 2.5 Gate

| Criteria | Verified |
|---|---|
| BehaviorTracker accumulates execution patterns with correct frequency counts | ☐ |
| BaselineStore persists snapshots and resumes on restart | ☐ |
| Stability detection correctly identifies when baseline has converged | ☐ |
| Auto-generated whitelist matches observed patterns with appropriate confidence scores | ☐ |
| Low-confidence / rare patterns are flagged for operator review | ☐ |
| Agent mode router correctly routes events based on discovery / shadow / enforcement mode | ☐ |
| Shadow mode logs "would-have" decisions without enforcing | ☐ |
| Discovery overhead < 1μs per event (does not degrade pipeline throughput) | ☐ |
| Integration test on live cluster produces valid baseline report | ☐ |

---

## Stage 3 — Validation & Risk Scoring (FR-02, FR-03)

> **Goal:** Build the process lineage validator and the multidimensional risk scoring engine, operating on the empirically-generated whitelist from Stage 2.5.

**Duration:** Weeks 7–8
**PRD References:** FR-02, FR-03
**Dependency:** Stage 2.5 (auto-generated whitelist provides the data foundation)

> **Note:** The whitelist used by the validator is now data-driven. The auto-generated `auto_whitelist.yaml` from Stage 2.5 serves as the primary input. The manually-curated `process_lineage_whitelist.yaml` can override or supplement it. Both are hot-reloadable.

### Step 3.1 — Process Lineage Whitelist Loader

| Item | Details |
|---|---|
| **Action** | Implement a YAML-based whitelist loader with hot-reload capability |
| **Deliverable** | `WhitelistLoader` class, `process_lineage_whitelist.yaml` config file |

**Tasks:**
- [ ] Define whitelist YAML schema:
  ```yaml
  whitelisted_lineages:
    - parent: nginx
      allowed_children: [nginx, sh]
    - parent: java
      allowed_children: [java]
    - parent: postgres
      allowed_children: [postgres, pg_dump]
    - parent: node
      allowed_children: [node, npm]
  ```
- [ ] Implement `WhitelistLoader` that parses YAML into a `dict[str, set[str]]` lookup
- [ ] Add file-watcher (inotify or polling) for hot-reload without restart
- [ ] Unit test: verify lookup correctness after load and after reload

### Step 3.2 — Lineage Validator Engine

| Item | Details |
|---|---|
| **Action** | Implement the validation logic that classifies events as `NORMAL`, `SUSPICIOUS`, or `ANOMALOUS` |
| **Deliverable** | `LineageValidator` class with `classify(event) -> Classification` |

**Tasks:**
- [ ] Classification logic:
  ```
  IF parent in whitelist AND child in allowed_children → NORMAL
  IF parent in whitelist AND child NOT in allowed_children → ANOMALOUS
  IF parent NOT in whitelist → SUSPICIOUS
  ```
- [ ] `Classification` enum: `NORMAL`, `SUSPICIOUS`, `ANOMALOUS`
- [ ] For `NORMAL` events: log to audit, do NOT forward to risk engine
- [ ] For `SUSPICIOUS`/`ANOMALOUS` events: forward to risk engine (Step 3.3)
- [ ] Benchmark: classification latency < 10ms per event
- [ ] Unit tests: cover all three classification paths with test events

### Step 3.3 — Risk Scoring Engine

| Item | Details |
|---|---|
| **Action** | Implement the three-dimensional risk scoring engine with externally configurable weights and tiers |
| **Deliverable** | `RiskEngine` class, `risk_scoring_policy.yaml` config file |

**Tasks:**
- [ ] Define risk scoring policy YAML:
  ```yaml
  weights:
    severity: 0.50
    context: 0.30
    asset_criticality: 0.20

  severity_scores:
    reverse_shell: 50
    chmod_suid: 45
    curl_download: 40
    bash_spawn: 35
    file_write_etc: 30
    default: 10

  context_scores:
    NORMAL: 0
    SUSPICIOUS: 15
    ANOMALOUS: 30

  asset_criticality:
    critical:
      namespaces: [database, secrets, auth]
      score: 20
    high:
      namespaces: [api, messaging]
      score: 15
    medium:
      namespaces: [backend]
      score: 10
    low:
      namespaces: [frontend, static]
      score: 5
    default_score: 10
  ```
- [ ] Implement `RiskEngine.calculate(event, classification) -> RiskScore`
- [ ] `RiskScore` dataclass: `severity_score`, `context_score`, `asset_score`, `total_score`
- [ ] Add Prometheus histogram: `ztre_risk_score_distribution`
- [ ] Benchmark: score calculation < 5ms per event
- [ ] Unit tests:
  - [ ] `nginx → bash` in `database` namespace → score ≥ 70 (Red)
  - [ ] unknown parent → `ls` in `frontend` namespace → score < 40 (Green)
  - [ ] `nginx → curl` in `api` namespace → score 40–69 (Yellow)

### Step 3.4 — Audit Logging for Validation & Scoring

| Item | Details |
|---|---|
| **Action** | Ensure every classification and score calculation is written to the structured audit log |
| **Deliverable** | Audit log entries with full input parameters for each scored event |

**Tasks:**
- [ ] Log entry format:
  ```json
  {
    "timestamp": "2026-09-08T14:30:00Z",
    "event_id": "uuid",
    "pod": "nginx-abc123",
    "namespace": "frontend",
    "parent": "nginx",
    "child": "bash",
    "classification": "ANOMALOUS",
    "severity_score": 35,
    "context_score": 30,
    "asset_score": 5,
    "total_risk_score": 70,
    "decision": "CONTAIN"
  }
  ```
- [ ] All fields populated for every `SUSPICIOUS`/`ANOMALOUS` event
- [ ] `NORMAL` events logged with classification only (no scoring fields)

---

### 🚪 Stage 3 Gate

| Criteria | Verified |
|---|---|
| Whitelist loads from YAML and hot-reloads on file change | ☐ |
| Validator classifies events into NORMAL / SUSPICIOUS / ANOMALOUS correctly | ☐ |
| NORMAL events are logged but NOT forwarded to risk engine | ☐ |
| Risk score formula produces correct results for all three zones | ☐ |
| Score configuration is externally modifiable via YAML | ☐ |
| All scored events appear in audit log with full parameters | ☐ |

---

## Stage 4 — Decision Engine & Automated Containment (FR-04, FR-05)

> **Goal:** Build the decision engine that maps risk scores to tiered actions, and the containment executor that patches Kubernetes pod labels to trigger Cilium network isolation.

**Duration:** Weeks 9–10
**PRD References:** FR-04, FR-05, NFR-01 (Non-Destructive), NFR-02 (Zero-Downtime)

### Step 4.1 — Decision Engine with Tiered Response

| Item | Details |
|---|---|
| **Action** | Implement the decision engine that evaluates risk scores against configurable thresholds |
| **Deliverable** | `DecisionEngine` class with `evaluate(risk_score) -> Action` |

**Tasks:**
- [ ] Define `Action` enum: `ALLOW_AND_LOG`, `LOG_AND_ALERT`, `AUTO_CONTAINMENT`
- [ ] Configurable thresholds via `agent_config.yaml`:
  ```yaml
  decision_engine:
    thresholds:
      green_max: 39      # < 40 → ALLOW & LOG
      yellow_max: 69     # 40–69 → LOG & ALERT
      # ≥ 70 → AUTO CONTAINMENT
  ```
- [ ] Implement threshold evaluation logic
- [ ] Benchmark: decision latency < 20ms
- [ ] Unit tests: boundary cases at 39, 40, 69, 70

### Step 4.2 — Alert Dispatcher

| Item | Details |
|---|---|
| **Action** | For Yellow zone events (40–69), emit structured alerts to configurable output channels |
| **Deliverable** | `AlertDispatcher` class with pluggable alert sinks |

**Tasks:**
- [ ] Define alert sink interface: `AlertSink.send(alert: Alert)`
- [ ] Implement `StdoutAlertSink` (JSON to stdout — for SIEM log collection)
- [ ] Implement `WebhookAlertSink` (HTTP POST to configurable URL — for Slack/PagerDuty)
- [ ] Alert payload includes: timestamp, pod, namespace, risk score, classification, recommended action
- [ ] Unit test: verify alert payloads match expected schema

### Step 4.3 — Kubernetes Containment Executor

| Item | Details |
|---|---|
| **Action** | For Red zone events (≥ 70), patch the target Pod with `ztre/quarantine: "true"` label via Kubernetes API |
| **Deliverable** | `ContainmentExecutor` struct |
| **Critical Constraint** | MUST NOT send SIGKILL — only label patching (NFR-01) |

**Tasks:**
- [ ] Implement `ContainmentExecutor.Quarantine(ctx context.Context, namespace, podName string) error`
- [ ] Use official `k8s.io/client-go`:
  ```go
  patchData := []byte(`{"metadata":{"labels":{"ztre/quarantine":"true"}}}`)
  _, err := clientset.CoreV1().Pods(namespace).Patch(
      ctx,
      podName,
      types.StrategicMergePatchType,
      patchData,
      metav1.PatchOptions{},
  )
  ```
- [ ] Retry logic: exponential backoff (`k8s.io/client-go/util/retry`), initial delay 100ms, max 3 retries
- [ ] Error handling: log API errors, increment `ztre_api_errors_total` metric
- [ ] **Safety check:** Verify no `SIGKILL` or process termination anywhere in the codebase
- [ ] Record containment in audit log with: timestamp, pod_name, namespace, risk_score
- [ ] Benchmark: patch applied within 1 second of decision

### Step 4.4 — End-to-End Pipeline Integration

| Item | Details |
|---|---|
| **Action** | Wire all modules together into the full event processing pipeline |
| **Deliverable** | Complete pipeline: EventCollector → Validator → RiskEngine → DecisionEngine → Containment/Alert |

**Tasks:**
- [ ] Wire modules in `cmd/ztre-agent/main.go`:
  ```
  EventCollector → EventParser → LineageValidator
                                        │
                                    [NORMAL] → log only
                                    [SUSPICIOUS/ANOMALOUS]
                                        │
                                        ▼
                                    RiskEngine
                                        │
                                        ▼
                                  DecisionEngine
                                    ├── ALLOW_AND_LOG → log
                                    ├── LOG_AND_ALERT → AlertDispatcher
                                    └── AUTO_CONTAINMENT → ContainmentExecutor
  ```
- [ ] Graceful shutdown handling (`os.Interrupt`, `syscall.SIGTERM` context cancellation)
- [ ] Health check endpoint at `/healthz` (HTTP 200)
- [ ] Integration test with mock Tetragon stream → verify full flow

---

### 🚪 Stage 4 Gate

| Criteria | Verified |
|---|---|
| Decision engine correctly routes scores to Green/Yellow/Red actions | ☐ |
| Yellow zone events produce structured alert payloads | ☐ |
| Red zone events patch pod labels within 1 second | ☐ |
| Cilium blocks all traffic to patched pods within 3 seconds | ☐ |
| No `SIGKILL` or process termination exists anywhere in the codebase | ☐ |
| Retry with backoff works on K8s API failures | ☐ |
| Full pipeline processes events end-to-end without errors | ☐ |

---

## Stage 5 — Integration Testing & Threat Simulation

> **Goal:** Deploy the complete ZTRE agent into the Kubernetes cluster, simulate real attack scenarios from the MITRE ATT&CK framework, and validate all success metrics (M1–M5).

**Duration:** Weeks 11–12
**PRD References:** §8 Success Metrics, MITRE ATT&CK alignment

### Step 5.1 — Agent Deployment as DaemonSet

| Item | Details |
|---|---|
| **Action** | Build the Docker image, deploy ZTRE as a DaemonSet to the cluster |
| **Deliverable** | ZTRE agent running on all worker nodes, ingesting live Tetragon events |

**Tasks:**
- [ ] Build and tag Docker image: `ztre-agent:v0.1.0`
- [ ] Create DaemonSet manifest:
  ```yaml
  apiVersion: apps/v1
  kind: DaemonSet
  metadata:
    name: ztre-agent
    namespace: ztre-system
  spec:
    selector:
      matchLabels:
        app: ztre-agent
    template:
      spec:
        serviceAccountName: ztre-agent
        containers:
        - name: ztre-agent
          image: ztre-agent:v0.1.0
          ports:
          - containerPort: 9090  # metrics
          - containerPort: 8080  # healthz
          resources:
            limits:
              cpu: "100m"
              memory: "128Mi"
  ```
- [ ] Apply DaemonSet, verify pods running on all worker nodes
- [ ] Verify `/metrics` endpoint accessible
- [ ] Verify `/healthz` returns 200

### Step 5.2 — Deploy Vulnerable Test Workloads

| Item | Details |
|---|---|
| **Action** | Deploy intentionally vulnerable applications in the `ztre-test` namespace to simulate attacks |
| **Deliverable** | Test pods running nginx, a simulated web app with RCE vulnerability |

**Tasks:**
- [ ] Deploy `nginx` pod (will be used for process lineage tests)
- [ ] Deploy a simple Python Flask app with a deliberate command injection endpoint
- [ ] Deploy a `postgres` pod (high asset-criticality target)
- [ ] Verify all pods are running and network-accessible to each other

### Step 5.3 — Attack Simulation Scenarios

| # | Scenario | MITRE ATT&CK | Expected ZTRE Behavior | Validates |
|---|---|---|---|---|
| **T1** | Spawn `bash` from `nginx` container | T1059.004 — Unix Shell | Classification: `ANOMALOUS`, Score ≥ 70, **Auto Containment** | M1, M4 |
| **T2** | Execute `curl` from `nginx` to exfiltrate data | T1041 — Exfiltration Over C2 | Classification: `ANOMALOUS`, Score ≥ 70, **Auto Containment** | M1, M3, M4 |
| **T3** | Reverse shell: `nginx → bash → nc` | T1059 + T1571 | Classification: `ANOMALOUS`, Score ≥ 70, **Auto Containment** | M1, M4 |
| **T4** | Legitimate `nginx → nginx` worker fork | — | Classification: `NORMAL`, **Allow & Log** | M2 |
| **T5** | Lateral movement: compromised pod → `postgres` | T1021 — Lateral Movement | Containment blocks network before data exfiltration | M3, M4 |
| **T6** | Unknown parent process runs `ls` in `frontend` | — | Classification: `SUSPICIOUS`, Score < 40, **Allow & Log** | M2 |

**Tasks:**
- [ ] Execute each scenario (T1–T6) manually via `kubectl exec`
- [ ] For each scenario, record:
  - [ ] Classification result (NORMAL / SUSPICIOUS / ANOMALOUS)
  - [ ] Risk score (S + C + A = total)
  - [ ] Decision (ALLOW / ALERT / CONTAIN)
  - [ ] Enforcement latency (timestamp delta: kernel event → Cilium deny)
  - [ ] Pod process state (confirm NOT killed)
- [ ] Verify quarantined pods still have running processes (`kubectl exec` into quarantined pod — should work for local commands but no network)

### Step 5.4 — Metrics Collection & Validation

| Metric (PRD §8) | Target | How to Measure |
|---|---|---|
| **M1 — Detection Accuracy** | ≥ 95% | (True threats detected) / (Total true threats simulated) × 100 |
| **M2 — False Positive Rate** | ≤ 2% | (Legitimate activity flagged) / (Total legitimate events) × 100 |
| **M3 — Enforcement Latency** | ≤ 5s P99 | Timestamp diff: Tetragon event → Cilium deny confirmed |
| **M4 — Containment Success** | ≥ 99% | (Successful containments without restart loop) / (Total containments) × 100 |
| **M5 — Computational Overhead** | CPU ≤ 2%, RAM ≤ 128MB | `kubectl top pod` on ZTRE agent pods during load |

**Tasks:**
- [ ] Run all 6 scenarios at least 10 times each
- [ ] Aggregate metrics into a results table
- [ ] Compare against PRD targets
- [ ] Document any deviations and root causes

### Step 5.5 — Forensic Artifact Verification

| Item | Details |
|---|---|
| **Action** | Confirm that quarantined pods preserve volatile forensic artifacts |
| **Deliverable** | Evidence that process memory, bash history, and open file descriptors are intact post-containment |

**Tasks:**
- [ ] After quarantine, `kubectl exec` into the contained pod
- [ ] Verify: `cat /proc/1/maps` (process memory map still accessible)
- [ ] Verify: `cat /root/.bash_history` (attacker command history preserved)
- [ ] Verify: `ls -la /proc/1/fd/` (open file descriptors still present)
- [ ] Verify: the pod did NOT restart (check `kubectl get pod` restart count = 0)

---

### 🚪 Stage 5 Gate

| Criteria | Verified |
|---|---|
| ZTRE agent deployed as DaemonSet and healthy on all nodes | ☐ |
| All 6 attack scenarios produce correct classification and action | ☐ |
| M1 (Detection Accuracy) ≥ 95% | ☐ |
| M2 (False Positive Rate) ≤ 2% | ☐ |
| M3 (Enforcement Latency) ≤ 5 seconds P99 | ☐ |
| M4 (Containment Success Rate) ≥ 99% | ☐ |
| M5 (CPU ≤ 2%, RAM ≤ 128MB) | ☐ |
| Forensic artifacts preserved in quarantined pods | ☐ |
| No Kubernetes restart loops triggered | ☐ |

---

## Stage 6 — Hardening, Documentation & Release

> **Goal:** Production-harden the agent, finalize documentation, and prepare for v1.0.0 release.

**Duration:** Weeks 13–14
**PRD References:** NFR-01 through NFR-06

### Step 6.1 — Security Hardening

**Tasks:**
- [ ] Audit RBAC: confirm agent SA has ONLY `patch` on `pods` (no escalation paths)
- [ ] Verify mTLS on all K8s API communication (in-cluster SA tokens use TLS by default)
- [ ] Ensure config files (`whitelist.yaml`, `risk_scoring_policy.yaml`) are mounted as read-only `ConfigMap` volumes
- [ ] Run container security scan on the ZTRE Docker image (Trivy / Grype)
- [ ] Ensure no hardcoded secrets or credentials in codebase

### Step 6.2 — Resilience Testing

**Tasks:**
- [ ] **Tetragon crash test:** Kill Tetragon pods → verify ZTRE reconnects automatically
- [ ] **K8s API unavailability test:** Block API access → verify retry with backoff → verify no crash
- [ ] **ZTRE agent crash test:** Kill ZTRE pod → verify DaemonSet restarts it → verify no data loss
- [ ] **High load test:** Generate 15,000 events/sec sustained → verify graceful degradation (no OOM, no crash)

### Step 6.3 — Observability Finalization

**Tasks:**
- [ ] Verify all Prometheus metrics are registered and incrementing:
  - `ztre_events_ingested_total`
  - `ztre_events_classified_total{status}`
  - `ztre_containment_actions_total`
  - `ztre_api_errors_total`
  - `ztre_risk_score_distribution`
  - `ztre_event_parse_duration_seconds`
- [ ] Create Grafana dashboard with:
  - Events ingested rate
  - Classification breakdown (NORMAL / SUSPICIOUS / ANOMALOUS)
  - Risk score distribution histogram
  - Containment action timeline
  - API error rate
- [ ] Verify structured JSON audit logs are forwarded to log aggregator

### Step 6.4 — Documentation

**Tasks:**
- [ ] Write `README.md` with: overview, architecture diagram, quick start, configuration reference
- [ ] Write `CONFIGURATION.md` detailing all YAML config files and their schemas
- [ ] Write `DEPLOYMENT.md` with step-by-step cluster setup and agent deployment
- [ ] Write `RUNBOOK.md` for SecOps: how to interpret alerts, how to manually release quarantine, how to tune thresholds
- [ ] Document API: all Prometheus metrics, health endpoints, log formats

### Step 6.5 — Release Packaging

**Tasks:**
- [ ] Tag release: `v1.0.0`
- [ ] Build and push production Docker image
- [ ] Create Helm chart for simplified deployment:
  ```
  helm install ztre ./charts/ztre \
    --namespace ztre-system \
    --set image.tag=v1.0.0
  ```
- [ ] Write `CHANGELOG.md` for v1.0.0
- [ ] Final review: walk through all PRD acceptance criteria (FR-01 through FR-05, NFR-01 through NFR-06)

---

### 🚪 Stage 6 Gate (Release Readiness)

| Criteria | Verified |
|---|---|
| Security audit passed (RBAC, mTLS, no hardcoded secrets, image scan) | ☐ |
| Resilience tests passed (Tetragon crash, API failure, agent crash, high load) | ☐ |
| All Prometheus metrics reporting correctly | ☐ |
| Grafana dashboard functional | ☐ |
| Documentation complete (README, CONFIG, DEPLOY, RUNBOOK) | ☐ |
| Helm chart deploys successfully on a clean cluster | ☐ |
| All PRD acceptance criteria verified | ☐ |

---

## Appendix A — Full PRD Traceability Matrix

| PRD Requirement | Stage | Steps |
|---|---|---|
| FR-01 (Event Interception) | Stage 2 | 2.1, 2.2, 2.3, 2.4 |
| FR-02 (Process Lineage Validation — Data Foundation) | Stage 2.5 | 2.5.1–2.5.7 |
| FR-02 (Process Lineage Validation — Engine) | Stage 3 | 3.1, 3.2 |
| FR-03 (Risk Assessment) | Stage 3 | 3.3, 3.4 |
| FR-04 (Decision Engine) | Stage 4 | 4.1, 4.2 |
| FR-05 (Automated Containment) | Stage 4 | 4.3, 4.4 |
| NFR-01 (Non-Destructive Mitigation) | Stage 4 | 4.3 (safety check) |
| NFR-02 (Zero-Downtime) | Stage 5 | 5.3, 5.5 |
| NFR-03 (Performance) | Stage 2, 2.5, 5 | 2.3 (throughput), 2.5.2 (tracker overhead), 5.4 (M5) |
| NFR-04 (Security) | Stage 1, 6 | 1.5, 6.1 |
| NFR-05 (Reliability) | Stage 2, 2.5, 6 | 2.1 (reconnect), 2.5.3 (baseline persistence), 6.2 |
| NFR-06 (Observability) | Stage 2, 2.5, 6 | 2.4, 2.5.2 (discovery metrics), 6.3 |
| O1 (Context-Aware Threat Validation) | Stage 2.5 | 2.5.2–2.5.4 (empirical context from observed behavior) |
| M1–M5 (Success Metrics) | Stage 5 | 5.3, 5.4 |

## Appendix B — Technology Stack Summary

| Component | Technology | Purpose |
|---|---|---|
| **Runtime** | Go (Golang) 1.22+ | ZTRE agent core |
| **Container** | Distroless / Alpine (multi-stage) | Agent packaging (~20MB) |
| **Orchestration** | Kubernetes (DaemonSet) | In-cluster agent deployment |
| **eBPF Observability** | Tetragon | Kernel-level event generation |
| **eBPF Networking** | Cilium | Network policy enforcement |
| **Event Transport** | gRPC (`github.com/cilium/tetragon/api/v1/tetragon`) | Tetragon → Agent event stream over unix socket |
| **Configuration** | YAML (`gopkg.in/yaml.v3`) | Policy files, whitelist, thresholds |
| **K8s Client** | `k8s.io/client-go` | In-cluster Pod label patching |
| **Metrics** | Prometheus (`client_golang`) | Agent observability |
| **Logging** | `go.uber.org/zap` (JSON) | High-performance structured audit logs |
| **Dashboards** | Grafana | Metrics visualization |
| **Testing** | `go test` (standard library) | Unit and integration tests |
| **Linting** | `golangci-lint` | Code quality |
| **Image Scanning** | Trivy / Grype | Container security |
| **Packaging** | Helm | Deployment automation |

---

*This roadmap is derived from [PRD.md](./PRD.md) v1.0.0. Each stage gate must be passed before proceeding to the next stage.*
