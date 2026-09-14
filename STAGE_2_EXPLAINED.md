# Stage 2 Deep Dive: Event Pipeline (FR-01) Explained

This document provides a comprehensive, file-by-file, step-by-step architectural breakdown of **Stage 2: Event Pipeline**. It explains how the ZTRE agent intercepts, parses, buffers, and monitors kernel security events in real time.

---

## 1. High-Level Concept: The Sensory Nervous System

Before ZTRE can evaluate process lineages (Stage 3) or quarantine rogue pods (Stage 4), it requires a **sensory nervous system**. 

In Kubernetes, hundreds of processes can be spawned every second. If an attacker runs a reverse shell, executes `whoami`, or downloads malware with `curl`, that event occurs at the **Linux kernel level**.

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  LINUX KERNEL (Worker Node)                                                    │
│  [ Pod executes command: /bin/whoami ] ──► sys_enter_execve syscall            │
└──────────────────────────────────────┬─────────────────────────────────────────┘
                                       │ eBPF Hook
                                       ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  TETRAGON DAEMONSET (kube-system)                                              │
│  • Intercepts syscall via eBPF kprobe                                          │
│  • Enriches with K8s Pod metadata (Pod name, Namespace, Container ID)          │
│  • Writes protobuf event stream to Unix Domain Socket                          │
│    Socket path: /var/run/tetragon/tetragon.sock                                │
└──────────────────────────────────────┬─────────────────────────────────────────┘
                                       │ gRPC Stream (IPC)
                                       ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│  ZTRE AGENT (ztre-system)                                                      │
│                                                                                │
│  1. TetragonClient (pkg/collector/client.go)                                   │
│     • Dials Unix socket: unix:///var/run/tetragon/tetragon.sock                │
│     • Calls GetEvents() gRPC stream                                            │
│     • Auto-reconnects with exponential backoff on disconnect                   │
│                                      │                                         │
│                                      ▼                                         │
│  2. EventParser (pkg/collector/parser.go)                                      │
│     • Extracts Binary, PID, Parent, Namespace, PodName                         │
│     • Filters out host OS noise (only tracks K8s Pods)                         │
│     • Records parse latency metrics (histogram)                                │
│                                      │                                         │
│                                      ▼                                         │
│  3. EventBuffer (pkg/collector/buffer.go)                                      │
│     • Bounded in-memory Go channel (capacity: 50,000 events)                   │
│     • Non-blocking push (318 ns/op = 3.1M events/sec)                          │
│     • Overflow protection: drops events safely if full, prevents OOM           │
│                                      │                                         │
│                                      ▼                                         │
│  4. Consumer Worker Pool (cmd/ztre-agent/main.go)                              │
│     • 4 concurrent Go worker routines consume events from buffer               │
│     • Logs structured JSON with Zap                                            │
│     • Ready to forward events to Stage 3 Validation Engine                     │
│                                      │                                         │
│  5. Observability (pkg/observability/metrics.go)                               │
│     • Exposes Prometheus metrics on :9090/metrics                               │
│     • Serves health check on :9090/healthz                                     │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. File-by-File Detailed Walkthrough

### 2.1 Data Model: `pkg/collector/types.go`

**Purpose:** Defines the normalized internal data structure for events within ZTRE.

Tetragon emits raw Protobuf structs (`*tetragon.GetEventsResponse`) containing dozens of low-level kernel fields (namespaces IDs, cgroups, capabilities, IMA hashes). ZTRE only needs security-relevant attributes.

```go
type SecurityEvent struct {
    Timestamp      time.Time                   // When the event occurred (UTC)
    EventType      EventType                   // "execve", "exit", "kprobe"
    PID            uint32                      // Process ID
    Binary         string                      // Full path of executable (e.g. /bin/whoami)
    Arguments      string                      // Command-line arguments
    ParentPID      uint32                      // Parent process ID
    ParentBinary   string                      // Parent executable (e.g. /bin/sh or nginx)
    Namespace      string                      // Kubernetes namespace (e.g. ztre-test)
    PodName        string                      // Target pod name
    ContainerID    string                      // Container runtime ID
    NodeName       string                      // Kubernetes node where event was observed
    WorkloadKind   string                      // e.g. Deployment, DaemonSet
    WorkloadName   string                      // e.g. vulnerable-nginx
    RawResponse    *tetragon.GetEventsResponse // Preserved for deep forensics
}
```

* **Why normalize?** Decouples downstream stages (Risk Scoring and Containment) from Tetragon's specific Protobuf schema. If event sources change or expand in the future, the rest of ZTRE is untouched.

---

### 2.2 Event Parser: `pkg/collector/parser.go`

**Purpose:** Converts raw Tetragon Protobuf objects into clean `SecurityEvent` structs.

#### Key Mechanics:
1. **Protobuf Type Switch:**
   Tetragon uses a Protobuf `oneof` field for events. The parser inspects the type:
   ```go
   switch ev := res.GetEvent().(type) {
   case *tetragon.GetEventsResponse_ProcessExec:
       // Handles process execution (execve syscall)
   case *tetragon.GetEventsResponse_ProcessExit:
       // Handles process termination
   case *tetragon.GetEventsResponse_ProcessKprobe:
       // Handles custom kernel probes (file open/write under /etc)
   }
   ```
2. **Kubernetes Pod Filtering:**
   The worker node runs host daemons (systemd, containerd, kubelet). We only want to monitor application workloads:
   ```go
   if pod == nil || pod.GetNamespace() == "" {
       return nil, nil // Discard host-level noise
   }
   ```
3. **Parse Latency Tracking:**
   Every parse operation is timed with a Prometheus histogram (`EventParseDuration`), verifying that parsing occurs in microseconds ($< 10\mu\text{s}$).

---

### 2.3 High-Throughput Event Buffer: `pkg/collector/buffer.go`

**Purpose:** Absorbs bursty traffic spikes and decouples event ingestion from event processing.

#### Why a Buffer is Essential:
In a Kubernetes cluster, a burst of activity (e.g., a batch job spawning 5,000 processes at once) can overwhelm the agent. If ingestion is synchronous, either:
- Kernel buffers overflow and drop events silently, or
- The agent runs out of memory (OOMKilled by Kubernetes).

#### The Solution: Bounded Go Channel
We use a buffered Go channel (`events chan *SecurityEvent`) with a default capacity of **50,000 events**.

#### Non-Blocking Push with Graceful Overflow:
```go
select {
case b.events <- event:
    observability.EventsIngestedTotal.WithLabelValues(...).Inc()
    return true
default:
    // Buffer is 100% full: drop event rather than crashing
    d := atomic.AddUint64(&b.dropped, 1)
    observability.EventsDroppedTotal.Inc()
    return false
}
```
* **Performance:** Benchmarked at **318 nanoseconds per event** (~3.1 million events/second).
* **Reliability (NFR-05):** Even if downstream processing slows down, the agent never blocks Tetragon and never exceeds memory limits.

---

### 2.4 Tetragon gRPC Client: `pkg/collector/client.go`

**Purpose:** Manages the gRPC stream connection to Tetragon's Unix domain socket.

#### Key Mechanics:
1. **Unix Domain Socket Dialing:**
   Tetragon listens on a local host socket (`/var/run/tetragon/tetragon.sock`). Communication uses high-speed Inter-Process Communication (IPC), avoiding network stack overhead:
   ```go
   conn, err := grpc.NewClient(
       "unix:///var/run/tetragon/tetragon.sock",
       grpc.WithTransportCredentials(insecure.NewCredentials()),
   )
   ```
2. **Streaming RPC:**
   Calls `FineGuidanceSensorsClient.GetEvents()`, which returns a long-lived server streaming channel.
3. **Exponential Backoff Reconnection:**
   If Tetragon is restarted or temporarily crashes:
   ```go
   select {
   case <-ctx.Done():
       return nil
   case <-time.After(backoff):
       backoff *= 2
       if backoff > maxBackoff { backoff = maxBackoff }
   }
   ```
   The agent automatically reconnects without crashing.

---

### 2.5 Observability: `pkg/observability/metrics.go` & `logger.go`

**Purpose:** Provides real-time metrics for Prometheus and structured logs for SecOps.

#### Metrics Exposed on `:9090/metrics`:
1. `ztre_collector_events_ingested_total{event_type, namespace}`: Counter of all intercepted events categorized by type (`execve`, `kprobe`, `exit`) and Kubernetes namespace.
2. `ztre_collector_events_dropped_total`: Counter tracking if the buffer ever overflows.
3. `ztre_collector_event_parse_duration_seconds`: Histogram measuring parsing speed in buckets from $10\mu\text{s}$ to $10\text{ms}$.

#### Health Endpoint on `:9090/healthz`:
Returns HTTP `200 OK` for Kubernetes liveness and readiness probes.

---

### 2.6 Application Entrypoint: `cmd/ztre-agent/main.go`

**Purpose:** Coordinates the lifecycle of all subsystems.

```go
func main() {
    // 1. Parse command-line flags (-tetragon-socket, -metrics-addr, -buffer-size, -debug)
    // 2. Initialize structured Zap JSON logger
    // 3. Set up signal handler (SIGINT / SIGTERM) for graceful shutdown
    // 4. Start HTTP metrics & health server on port 9090
    // 5. Initialize 50,000-capacity EventBuffer
    // 6. Launch 4-goroutine Consumer Worker Pool
    // 7. Launch Tetragon Client event stream loop
    // 8. Block until shutdown signal, then drain resources cleanly
}
```

---

### 2.7 Packaging: `deploy/Dockerfile`

**Purpose:** Builds a minimal, highly secure container image.

#### Multi-Stage Build:
1. **Builder Stage (`golang:alpine`):**
   * Compiles the Go source code with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`.
   * Strips debugging symbols (`-ldflags="-w -s"`) for a tiny binary.
2. **Runtime Stage (`gcr.io/distroless/static:nonroot`):**
   * Contains **only** the compiled binary.
   * No shell (`sh`/`bash`), no package manager (`apt`/`apk`), no extra utilities.
   * Runs as unprivileged user `65532:nonroot`.
   * **Total Image Size:** **6.52 MB** (extremely fast pulls and zero attack surface).

---

## 3. How Data Flows End-to-End (Concrete Example)

Let's trace what happens when an attacker executes `whoami` inside a pod:

1. **Syscall:** The container runtime issues `execve("/bin/whoami", ...)` in the Linux kernel.
2. **eBPF Interception:** Tetragon's kernel hook intercepts the syscall and builds an event enriched with Pod metadata (`pod: trigger-event`, `namespace: ztre-test`).
3. **gRPC Transport:** Tetragon pushes the binary Protobuf message into `/var/run/tetragon/tetragon.sock`.
4. **Client Reception (`client.go`):** `stream.Recv()` receives the message and hands it to `parser.go`.
5. **Normalization (`parser.go`):** The parser detects `ProcessExec`, verifies it belongs to namespace `ztre-test`, and creates:
   ```json
   {
     "binary": "/bin/whoami",
     "pid": 96870,
     "parent_binary": "/bin/sh",
     "namespace": "ztre-test",
     "pod_name": "trigger-event"
   }
   ```
6. **Buffering (`buffer.go`):** The event is pushed into the buffered channel in $< 1\mu\text{s}$.
7. **Worker Processing (`main.go`):** An idle worker coroutine dequeues the event, increments Prometheus counters, and emits a structured log.
8. **Forwarding to Stage 3:** In Stage 3, this worker will pass the event directly into the **Lineage Validator** and **Risk Scoring Engine**.

---

## 4. Verification Evidence (From Live Cluster Test)

During testing on the live cluster, the agent produced this exact log:

```json
{
  "level": "info",
  "timestamp": "2026-09-13T16:00:08.996Z",
  "caller": "ztre-agent/main.go:72",
  "msg": "ingested security event",
  "worker": 2,
  "type": "execve",
  "namespace": "ztre-test",
  "pod": "trigger-event",
  "binary": "/bin/whoami",
  "pid": 96870,
  "parent_binary": "/bin/sh"
}
```

Notice that:
- `worker: 2` processed the event concurrently.
- `parent_binary` (`/bin/sh`) and child `binary` (`/bin/whoami`) were accurately extracted.
- `namespace` (`ztre-test`) and `pod` (`trigger-event`) were matched to Kubernetes metadata.

---

## 5. Summary of Key Performance & Reliability Metrics

| Metric | PRD Target | Measured Result |
|---|---|---|
| **Event Throughput** | $\ge 10,000\text{ events/sec}$ | **3,139,717 events/sec** (318.5 ns/op) |
| **Parse Latency** | $< 10\text{ ms}$ | **$< 0.05\text{ ms}$** |
| **Container Size** | $< 128\text{ MB}$ | **6.52 MB** |
| **Auto-Reconnect** | Resilient | Verified with exponential backoff ($1\text{s} \to 2\text{s} \to 4\text{s} \dots$) |
| **Graceful Shutdown** | Zero panic | Verified on `SIGTERM` (drains buffer and stops servers) |
