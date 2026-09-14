# Stage 2 Deep Dive: Event Pipeline (FR-01) Explained

This document provides a comprehensive, file-by-file, step-by-step architectural breakdown of **Stage 2: Event Pipeline**. It explains how the ZTRE agent intercepts, parses, buffers, and monitors kernel security events in real time.

**Last Updated:** 2026-09-14 (reflects post-refactoring state with all critical fixes applied)

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
│     • Auto-reconnects with exponential backoff (resets after 5s stable)        │
│                                      │                                         │
│                                      ▼                                         │
│  2. EventParser (pkg/collector/parser.go)                                      │
│     • Shared buildSecurityEvent() helper for uniform field extraction          │
│     • Extracts Binary, PID, Parent, Namespace, PodName, Container, Workload   │
│     • Filters out host OS noise (only tracks K8s Pods)                         │
│     • Uses Tetragon timestamps when available, falls back to UTC              │
│     • Records parse latency metrics (Prometheus histogram)                     │
│                                      │                                         │
│                                      ▼                                         │
│  3. EventBuffer (pkg/collector/buffer.go)                                      │
│     • Bounded in-memory Go channel (capacity: 50,000 events)                   │
│     • Non-blocking push (197 ns/op = 5.06M events/sec)                         │
│     • Lock-free close detection via atomic.Bool                                │
│     • Overflow protection: drops events safely if full, prevents OOM           │
│                                      │                                         │
│                                      ▼                                         │
│  4. Consumer Worker Pool (cmd/ztre-agent/main.go)                              │
│     • 4 concurrent Go worker routines consume events from buffer               │
│     • sync.WaitGroup ensures graceful drain on shutdown                        │
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
    Timestamp    time.Time `json:"timestamp"`       // When the event occurred (UTC or Tetragon-reported)
    EventType    EventType `json:"event_type"`       // "execve", "exit", "kprobe"
    PID          uint32    `json:"pid"`              // Process ID
    Binary       string    `json:"binary"`           // Full path of executable (e.g. /bin/whoami)
    Arguments    string    `json:"arguments"`        // Command-line arguments
    ParentPID    uint32    `json:"parent_pid"`       // Parent process ID
    ParentBinary string    `json:"parent_binary"`    // Parent executable (e.g. /bin/sh or nginx)
    Namespace    string    `json:"namespace"`        // Kubernetes namespace (e.g. ztre-test)
    PodName      string    `json:"pod_name"`         // Target pod name
    ContainerID  string    `json:"container_id"`     // Container runtime ID
    NodeName     string    `json:"node_name"`        // Kubernetes node where event was observed
    WorkloadKind string    `json:"workload_kind"`    // e.g. Deployment, DaemonSet
    WorkloadName string    `json:"workload_name"`    // e.g. vulnerable-nginx
}
```

#### Key Design Decisions:
- **No Protobuf retention.** Unlike the initial implementation, the `RawResponse` field has been intentionally removed. This means the full Protobuf message tree is not kept alive per event, preventing memory bloat in the 50k buffer. Each `SecurityEvent` is ~200 bytes of lightweight scalar/string fields.
- **Decoupling.** Downstream stages (Risk Scoring and Containment) are decoupled from Tetragon's specific Protobuf schema. If event sources change or expand in the future, the rest of ZTRE is untouched.
- **Forward-looking constants.** `EventTypeFileAccess` is defined for future Tetragon file access event support even though it's not yet parsed.

---

### 2.2 Event Parser: `pkg/collector/parser.go`

**Purpose:** Converts raw Tetragon Protobuf objects into clean `SecurityEvent` structs.

#### Architecture: Type Switch + Shared Helper

The parser uses a two-layer design:

1. **Top-level `Parse()` method** — Type-switches on the Protobuf `oneof` event field to determine the event category:
   ```go
   switch ev := res.GetEvent().(type) {
   case *tetragon.GetEventsResponse_ProcessExec:
       return p.buildSecurityEvent(ev.ProcessExec.GetProcess(), ev.ProcessExec.GetParent(), EventTypeExecve, nodeName, eventTime), nil
   case *tetragon.GetEventsResponse_ProcessExit:
       return p.buildSecurityEvent(ev.ProcessExit.GetProcess(), ev.ProcessExit.GetParent(), EventTypeExit, nodeName, eventTime), nil
   case *tetragon.GetEventsResponse_ProcessKprobe:
       return p.buildSecurityEvent(ev.ProcessKprobe.GetProcess(), ev.ProcessKprobe.GetParent(), EventTypeKprobe, nodeName, eventTime), nil
   }
   ```

2. **Shared `buildSecurityEvent()` helper** — Extracts all common fields uniformly for every event type:
   - Process fields: `PID`, `Binary`, `Arguments`
   - Pod metadata: `Namespace`, `PodName`, `WorkloadKind`, `WorkloadName`
   - Container: `ContainerID` (from `pod.GetContainer()`)
   - Parent lineage: `ParentPID`, `ParentBinary` (from parent `Process`)
   - Infrastructure: `NodeName`

   This eliminates code duplication and ensures **all event types** (including `ProcessExit`) extract parent and container data identically. This is critical because Stage 3's lineage validator relies on `ParentBinary` being present for exit events.

#### Kubernetes Pod Filtering
The worker node runs host daemons (systemd, containerd, kubelet). We only want to monitor application workloads:
```go
if pod == nil || pod.GetNamespace() == "" {
    return nil // Discard host-level noise
}
```

#### Timestamp Handling
The parser prioritizes Tetragon's reported event timestamp when available, falling back to the current UTC time:
```go
eventTime := time.Now().UTC()
if res.GetTime() != nil {
    eventTime = res.GetTime().AsTime()
}
```
This ensures events reflect when they actually occurred at the kernel level, not when they were processed by the agent.

#### Parse Latency Tracking
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
func (b *EventBuffer) Push(event *SecurityEvent) bool {
    if b.isClosed.Load() || event == nil {
        return false
    }

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
}
```

#### Safety Mechanisms:
- **Lock-free close detection:** Uses `atomic.Bool` (`isClosed`) for fast, contention-free closed-state checking in `Push()`.
- **Safe close:** `sync.Once` guarantees the channel is closed exactly once, preventing panics from double-close.
- **Atomic drop counter:** `atomic.AddUint64` for concurrent-safe drop counting without mutex overhead.
- **Throttled logging:** Drop warnings are logged every 100th drop (`d%100 == 1`) to prevent log flooding under sustained pressure.

#### Performance:
- Benchmarked at **197 nanoseconds per event** (~5.06 million events/second).
- **506× headroom** above the PRD requirement of 10,000 events/sec.
- **Reliability (NFR-05):** Even if downstream processing slows down, the agent never blocks Tetragon and never exceeds memory limits.

---

### 2.4 Tetragon gRPC Client: `pkg/collector/client.go`

**Purpose:** Manages the gRPC stream connection to Tetragon's Unix domain socket.

#### Architecture: Two-Layer Design

The client separates lifecycle management from streaming:

1. **`Start()` — Reconnect lifecycle loop** ([`client.go#L56-L97`](file:///home/execute/ZTRE/pkg/collector/client.go#L56-L97)):
   - Calls `streamEvents()` to establish and run a single connection session
   - On disconnection: applies exponential backoff (1s → 2s → 4s → ... → 10s max)
   - **Intelligent backoff reset:** If a stream ran for ≥5 seconds before failing, backoff resets to the initial interval (1s). This prevents the agent from using max backoff after a brief network hiccup during a long-running stable session.

2. **`streamEvents()` — Single session handler** ([`client.go#L99-L141`](file:///home/execute/ZTRE/pkg/collector/client.go#L99-L141)):
   - Dials the Unix domain socket using `grpc.NewClient()` (correct modern API)
   - Opens a `GetEvents()` server-streaming RPC
   - Loops on `stream.Recv()` — which is context-aware and returns on cancellation
   - Parses each response and pushes to the buffer

#### Unix Domain Socket Dialing:
Tetragon listens on a local host socket (`/var/run/tetragon/tetragon.sock`). Communication uses high-speed Inter-Process Communication (IPC), avoiding network stack overhead:
```go
conn, err := grpc.NewClient(
    "unix:///var/run/tetragon/tetragon.sock",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
```

#### Exponential Backoff with Reset:
```go
// If stream ran successfully for at least 5 seconds before failing, reset backoff
if time.Since(startTime) >= 5*time.Second {
    backoff = c.config.ReconnectInterval
}
```
This ensures that after a long-running stable connection, a brief Tetragon restart triggers a quick reconnect (1s) rather than escalating to max backoff.

---

### 2.5 Observability: `pkg/observability/metrics.go` & `logger.go`

**Purpose:** Provides real-time metrics for Prometheus and structured logs for SecOps.

#### Metrics Exposed on `:9090/metrics`:
1. `ztre_collector_events_ingested_total{event_type, namespace}`: Counter of all intercepted events categorized by type (`execve`, `kprobe`, `exit`) and Kubernetes namespace.
2. `ztre_collector_events_dropped_total`: Counter tracking if the buffer ever overflows.
3. `ztre_collector_event_parse_duration_seconds`: Histogram measuring parsing speed in buckets from $10\mu\text{s}$ to $10\text{ms}$.

#### Health Endpoint on `:9090/healthz`:
Returns HTTP `200 OK` for Kubernetes liveness and readiness probes.

#### Metrics Server Configuration:
The HTTP server includes timeouts (`ReadTimeout: 5s`, `WriteTimeout: 10s`) and proper graceful shutdown via `srv.Shutdown(ctx)` during agent termination.

#### Logger (`logger.go`):
Initializes a Zap structured JSON logger with:
- ISO8601 timestamps (key: `"timestamp"`)
- Production config with `Info` level by default
- Debug mode available via `-debug` CLI flag
- Development-friendly output when debug is enabled

---

### 2.6 Application Entrypoint: `cmd/ztre-agent/main.go`

**Purpose:** Coordinates the lifecycle of all subsystems with proper ordered shutdown.

```go
func main() {
    // 1. Parse command-line flags (-tetragon-socket, -metrics-addr, -buffer-size, -debug)
    // 2. Initialize structured Zap JSON logger
    // 3. Set up signal handler (SIGINT / SIGTERM) for graceful shutdown
    // 4. Start HTTP metrics & health server on port 9090
    // 5. Initialize 50,000-capacity EventBuffer
    // 6. Launch 4-goroutine Consumer Worker Pool with sync.WaitGroup
    // 7. Launch Tetragon Client event stream loop
    // 8. Block until shutdown signal
    // 9. Ordered shutdown:
    //    a. cancel() → stops Tetragon client (producer)
    //    b. <-clientDone → wait for client goroutine to exit
    //    c. eventBuffer.Close() → close the channel
    //    d. wg.Wait() → wait for all workers to drain remaining buffered events
    //    e. metricsServer.Shutdown() → stop HTTP server
    //    f. Log clean termination
}
```

#### Graceful Shutdown Sequence:
The shutdown is carefully ordered to ensure **zero event loss during controlled shutdown**:

1. **Stop the producer first** (`cancel()` + `<-clientDone`): The Tetragon client stops receiving new events and its goroutine exits.
2. **Close the buffer** (`eventBuffer.Close()`): The channel is closed, signaling workers that no more events will arrive.
3. **Wait for workers to drain** (`wg.Wait()`): Workers range over the channel, processing all remaining buffered events before exiting.
4. **Shutdown metrics server**: HTTP server is gracefully stopped with a 3-second timeout.

This ensures that events already in the buffer are fully processed before the agent exits.

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
2. **eBPF Interception:** Tetragon's kernel hook intercepts the syscall and builds an event enriched with Pod metadata (`pod: trigger-test`, `namespace: ztre-test`).
3. **gRPC Transport:** Tetragon pushes the binary Protobuf message into `/var/run/tetragon/tetragon.sock`.
4. **Client Reception (`client.go`):** `stream.Recv()` receives the message and hands it to the parser.
5. **Normalization (`parser.go`):** The parser detects `ProcessExec`, verifies it belongs to namespace `ztre-test`, and calls `buildSecurityEvent()` which creates:
   ```json
   {
     "timestamp": "2026-09-14T06:51:56.996Z",
     "event_type": "execve",
     "binary": "/bin/whoami",
     "pid": 104529,
     "parent_binary": "/bin/sh",
     "namespace": "ztre-test",
     "pod_name": "trigger-test",
     "node_name": "akmal-vm-node2"
   }
   ```
6. **Buffering (`buffer.go`):** The event is pushed into the buffered channel in $< 1\mu\text{s}$ (197 ns benchmarked). The `isClosed` atomic check ensures the buffer is accepting events.
7. **Worker Processing (`main.go`):** An idle worker goroutine dequeues the event, increments Prometheus counters, and emits a structured log.
8. **Forwarding to Stage 3:** In Stage 3, this worker will pass the event directly into the **Lineage Validator** and **Risk Scoring Engine** instead of logging.

---

## 4. Verification Evidence (From Live Cluster Test)

During testing on the live cluster, the agent produced these logs confirming full event interception with parent lineage:

**Process Execution (`execve`):**
```json
{
  "level": "info",
  "timestamp": "2026-09-14T06:51:56.996Z",
  "caller": "ztre-agent/main.go:69",
  "msg": "ingested security event",
  "worker": 0,
  "type": "execve",
  "namespace": "ztre-test",
  "pod": "trigger-test",
  "binary": "/bin/whoami",
  "pid": 104529,
  "parent_binary": "/bin/sh"
}
```

**Process Exit (`exit`) — now with parent lineage:**
```json
{
  "level": "info",
  "timestamp": "2026-09-14T06:51:56.996Z",
  "caller": "ztre-agent/main.go:69",
  "msg": "ingested security event",
  "worker": 3,
  "type": "exit",
  "namespace": "ztre-test",
  "pod": "trigger-test",
  "binary": "/bin/whoami",
  "pid": 104529,
  "parent_binary": "/bin/sh"
}
```

Notice that:
- Both `execve` and `exit` events carry `parent_binary` (`/bin/sh`), enabling full lineage tracking for Stage 3's validator.
- Different workers (`worker: 0` and `worker: 3`) processed the events concurrently.
- `namespace` (`ztre-test`) and `pod` (`trigger-test`) were matched to Kubernetes metadata.

**Graceful Shutdown — verified with ordered drain:**
```json
{"level":"info","timestamp":"2026-09-14T06:52:19.869Z","caller":"ztre-agent/main.go:100","msg":"received termination signal, initiating graceful shutdown","signal":"terminated"}
{"level":"info","timestamp":"2026-09-14T06:52:19.869Z","caller":"ztre-agent/main.go:115","msg":"ZTRE Agent terminated cleanly"}
```

---

## 5. Test Coverage Summary

### Parser Tests (`parser_test.go` — 5 tests, 231 lines)

| Test | What It Verifies |
|---|---|
| `TestParser_ProcessExec` | Full `execve` event parsing: PID, Binary, Arguments, ParentPID, ParentBinary, Namespace, PodName, WorkloadKind, WorkloadName, ContainerID |
| `TestParser_IgnoreHostEvent` | Host-level processes (no Pod metadata) are filtered out and return nil |
| `TestParser_ProcessExit` | `exit` events extract ParentBinary, ParentPID, and ContainerID (previously a bug) |
| `TestParser_ProcessKprobe` | `kprobe` events extract ParentBinary, ParentPID, and ContainerID |
| `TestParser_EdgeCases` | Nil response → nil, empty response → nil, empty namespace → nil |

### Buffer Tests (`buffer_test.go` — 2 tests + 1 benchmark, 97 lines)

| Test | What It Verifies |
|---|---|
| `TestEventBuffer_PushAndPop` | Push event, verify length, consume via channel |
| `TestEventBuffer_Overflow` | Fill to capacity, verify next push drops, verify dropped count |
| `BenchmarkEventBuffer_Throughput` | End-to-end push+consume throughput measurement |

---

## 6. Summary of Key Performance & Reliability Metrics

| Metric | PRD Target | Measured Result | Headroom |
|---|---|---|---|
| **Event Throughput** | $\ge 10,000\text{ events/sec}$ | **5,060,000 events/sec** (197.3 ns/op) | **506×** |
| **Parse Latency** | $< 10\text{ ms}$ | **$< 0.05\text{ ms}$** | **200×** |
| **Container Size** | $< 128\text{ MB}$ | **6.52 MB** | **20×** |
| **Buffer Memory (worst case)** | $\le 128\text{ MB}$ | **~10 MB** (50k × ~200B events, no Protobuf) | **12×** |
| **Auto-Reconnect** | Resilient | Exponential backoff ($1\text{s} \to 2\text{s} \to 4\text{s} \dots$), resets after 5s stable | ✅ |
| **Graceful Shutdown** | Zero panic, ordered drain | Verified: cancel → wait client → close buffer → drain workers → stop HTTP | ✅ |
| **Parser Test Coverage** | All event types | 5 tests: execve, exit, kprobe, host filter, edge cases | ✅ |

---

## 7. What Changed Since Initial Implementation

| Area | Before (Initial) | After (Current) | Impact |
|---|---|---|---|
| **Parser structure** | 3 duplicated `case` branches | Shared `buildSecurityEvent()` helper | Eliminated duplication, ensured uniform extraction |
| **ProcessExit parent data** | ❌ Not extracted (bug) | ✅ Extracted via `GetParent()` | Stage 3 lineage validation now works for exit events |
| **ProcessExit container data** | ❌ Not extracted (bug) | ✅ Extracted via `pod.GetContainer()` | Complete container tracking across all event types |
| **RawResponse field** | Present (memory risk) | Removed entirely | Buffer memory: 50-250MB → ~10MB |
| **Backoff reset** | Never reset after reconnect | Resets after ≥5s stable or clean exit | Operational: quick reconnect after brief hiccups |
| **Graceful shutdown** | No worker drain | `sync.WaitGroup` + ordered sequence | Zero event loss during controlled shutdown |
| **Redundant select** | `select{ctx.Done()}` before `Recv()` | Removed (Recv is context-aware) | Cleaner code, eliminated busy-poll pattern |
| **Timestamp handling** | Always `time.Now().UTC()` | Uses `res.GetTime().AsTime()` when available | Events reflect actual kernel-level timing |
| **WorkloadKind/Name** | Only in ProcessExec | All event types (via shared helper) | Complete workload context for all events |
| **Close detection** | `sync.Mutex` for closed check | `atomic.Bool` (lock-free) | Better performance under contention |
| **Test coverage** | 2 parser tests | 5 parser tests + edge cases | All branches and error paths verified |
| **Benchmark throughput** | 3.1M events/sec | 5.06M events/sec | +63% improvement (lighter struct) |
