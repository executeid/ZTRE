# Stage 2.5 Deep Dive: Behavioral Discovery & Baseline Learning

This document provides a comprehensive, file-by-file breakdown of **Stage 2.5: Behavioral Discovery & Baseline Learning** — the data-driven foundation that feeds the validation and risk scoring pipeline in Stage 3.

**Last Updated:** 2026-09-14 (initial implementation)

---

## 1. Why This Stage Exists

Before ZTRE can evaluate process lineages (Stage 3) or quarantine rogue pods (Stage 4), it needs to know what **normal behavior looks like** in each specific cluster. Without this, the process lineage whitelist would be a manually-crafted guess — leading to excessive false positives or missed threats.

Stage 2.5 solves this by:
1. **Passively observing** all parent→child execution patterns across the cluster
2. **Building frequency maps** per namespace/workload
3. **Detecting when the baseline stabilizes** (no new patterns for a configurable period)
4. **Auto-generating a whitelist** from observed data with confidence scores
5. **Enabling shadow mode** for dry-run validation before enforcement

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  AGENT OPERATIONAL MODES                                                       │
│                                                                                │
│  DISCOVERY ──────────► SHADOW ──────────► ENFORCEMENT                          │
│  (passive observe)      (dry-run)          (full pipeline)                     │
│                                                                                │
│  • Track patterns       • Track + classify  • Classify + score                 │
│  • Build baseline       • Log decisions     • Decide + contain                 │
│  • Detect stability     • No enforcement    • Full enforcement                 │
│  • Auto-gen whitelist   • Validate WL       • Production mode                  │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. File-by-File Walkthrough

### 2.1 Data Model: `pkg/discovery/types.go`

**Purpose:** Defines all data structures used by the discovery engine.

| Type | Purpose |
|---|---|
| `AgentMode` | Enum: `discovery`, `shadow`, `enforcement` |
| `StabilityStatus` | Enum: `LEARNING`, `STABILIZING`, `STABLE` |
| `ExecutionPattern` | One observed parent→child pair with frequency, timestamps, node list |
| `PatternStats` | Computed metrics: frequency, z-score, confidence, burst/recurring flags |
| `LineageProfile` | Aggregated baseline for one workload |
| `BaselineSnapshot` | Full tracker state at one point in time (for persistence) |
| `BaselineReport` | Human-readable discovery output |
| `AnomalyCandidate` | Pattern flagged as suspicious even during learning |
| `WhitelistEntry` | One entry in the auto-generated whitelist |
| `WhitelistConfig` | Top-level auto-generated whitelist YAML structure |

### 2.2 Behavior Tracker: `pkg/discovery/tracker.go`

**Purpose:** Core engine that receives `SecurityEvent`s and maintains in-memory frequency maps of parent→child relationships.

**Key Design Decisions:**
- **Only `execve` events define lineage.** Exit and kprobe events are counted for total event tracking but don't create new parent→child patterns.
- **`filepath.Base()` normalization.** Binaries are stored as base names (`nginx` not `/usr/sbin/nginx`) so the whitelist is path-independent.
- **`sync.RWMutex` for concurrency.** Multiple worker goroutines call `Track()` concurrently. Read-heavy operations (stats, profiles) use `RLock`.
- **Statistical analysis built-in.** `GetStats()` computes frequency, z-score, burst detection, and confidence for each pattern — used by the reporter to decide what goes in the whitelist.

**Confidence Scoring:**
```
≥ 100 occurrences AND recurring → 0.99
≥ 50  occurrences AND recurring → 0.95
≥ 10  occurrences AND recurring → 0.85
≥ 10  occurrences              → 0.70
≥ 3   occurrences              → 0.50
< 3   occurrences              → 0.30 (review_flag: true)
```

### 2.3 Baseline Store: `pkg/discovery/baseline.go`

**Purpose:** Persists behavioral snapshots and detects when the baseline has converged.

**Stability Detection:**
- `LEARNING`: New patterns still being discovered frequently
- `STABILIZING`: No new patterns for ≥ half the stability threshold
- `STABLE`: No new patterns for ≥ the full stability threshold (default: 4 hours)

**Persistence:**
- Periodic JSON snapshots to `data/discovery/baseline_YYYYMMDD_HHMMSS.json`
- `baseline_latest.json` always points to the most recent snapshot
- On agent restart, `LoadLatestSnapshot()` resumes learning from where it left off
- Final snapshot saved on graceful shutdown

### 2.4 Baseline Reporter: `pkg/discovery/reporter.go`

**Purpose:** Generates human-readable reports and auto-generates `auto_whitelist.yaml`.

**Report Output:** `data/discovery/baseline_report.json` containing:
- Learning window (start/end)
- Total events observed
- Unique lineage pairs
- Per-workload behavioral profiles
- Anomaly candidates (rare patterns with z-score < -1.5)
- Stability status and recommendation

**Whitelist Output:** `config/auto_whitelist.yaml` containing:
- YAML header with generation metadata
- Whitelist entries sorted by confidence (highest first)
- `review_flag: true` on low-confidence entries
- Fully compatible with the Stage 3 whitelist loader schema

### 2.5 Config Loader: `pkg/config/config.go`

**Purpose:** Loads `agent_config.yaml` with the new mode and discovery settings.

Supports `Duration` YAML unmarshaling for `72h`, `30m`, etc. Falls back to sensible defaults when fields are missing.

### 2.6 Agent Mode Router: `cmd/ztre-agent/main.go`

**Purpose:** Routes events through the mode-aware pipeline.

```
EventBuffer ──► Worker Pool ──► Mode Router
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                DISCOVERY       SHADOW         ENFORCEMENT
                    │               │               │
              Track(event)    Track(event)     [Stage 3+4]
                              + dry-run log
```

**New CLI flags:**
- `--config`: Path to agent config YAML (default: `config/agent_config.yaml`)
- `--mode`: Override agent mode (discovey/shadow/enforcement)
- `--generate-report`: Generate baseline report and whitelist, then exit

**Shutdown behavior in discovery mode:**
1. Stop Tetragon client (producer)
2. Close buffer, drain workers
3. Save final baseline snapshot
4. Generate report + auto-whitelist
5. Shutdown metrics server

---

## 3. Prometheus Metrics Added

| Metric | Type | Description |
|---|---|---|
| `ztre_discovery_patterns_observed_total` | Counter | Unique parent→child patterns discovered |
| `ztre_discovery_events_tracked_total` | Counter | Total events processed in discovery mode |
| `ztre_discovery_stability_status` | Gauge | 0=LEARNING, 1=STABILIZING, 2=STABLE |
| `ztre_agent_mode` | Gauge | 0=discovery, 1=shadow, 2=enforcement |
| `ztre_shadow_decisions_total{action}` | Counter | Shadow mode "would-have" decisions |

---

## 4. Test Coverage

### Discovery Tests (`pkg/discovery/discovery_test.go` — 15 tests + 2 benchmarks)

| Test | What It Verifies |
|---|---|
| `TestTracker_BasicTracking` | Track events, verify count and pattern fields |
| `TestTracker_MultipleNamespaces` | Same parent→child in different namespaces creates separate patterns |
| `TestTracker_IgnoresNonExecve` | Exit events don't create patterns but are counted |
| `TestTracker_NilEvent` | Nil events handled safely |
| `TestTracker_NodeTracking` | Nodes deduplicated per pattern |
| `TestTracker_ConcurrentAccess` | 4 goroutines × 100 events, race-free |
| `TestTracker_GetStats` | High-frequency pattern gets high confidence; rare gets review flag |
| `TestTracker_GetProfiles` | Per-workload profile aggregation |
| `TestBaselineStore_SaveLoadRoundTrip` | Save snapshot → load in fresh tracker → patterns match |
| `TestBaselineStore_StabilityDetection` | LEARNING → STABLE transition; new pattern resets |
| `TestBaselineStore_NoSnapshot` | Missing snapshot dir loads gracefully |
| `TestReporter_GenerateReport` | Report contains correct lineage count and event total |
| `TestReporter_GenerateWhitelist` | High-confidence entries, correct children, correct parent |
| `TestReporter_WriteFiles` | Report JSON and whitelist YAML are written and parseable |
| `TestConfigLoad` | Config values parsed from YAML |
| `BenchmarkTracker_Track` | Single-goroutine tracking throughput |
| `BenchmarkTracker_TrackParallel` | Multi-goroutine tracking throughput |

### Config Tests (`pkg/config/config_test.go` — 3 tests)

| Test | What It Verifies |
|---|---|
| `TestLoadAgentConfig` | Full config parsing with all fields |
| `TestLoadAgentConfig_Defaults` | Minimal config fills in defaults |
| `TestLoadAgentConfig_Missing` | Missing file returns error |

---

## 5. How to Use

### Discovery Mode (default)
```bash
# Start agent in discovery mode (default)
./ztre-agent --tetragon-socket /var/run/tetragon/tetragon.sock

# Or explicitly
./ztre-agent --mode discovery
```

### Generate Report from Existing Data
```bash
./ztre-agent --generate-report
# Outputs: data/discovery/baseline_report.json
# Outputs: config/auto_whitelist.yaml
```

### Shadow Mode (dry-run validation)
```bash
./ztre-agent --mode shadow
# Continues learning + logs what validator WOULD do
```

### Mode Override
```bash
# Config says "discovery" but CLI overrides to "shadow"
./ztre-agent --mode shadow --config config/agent_config.yaml
```

---

## 6. What Changed from Stage 2

| Area | Stage 2 | Stage 2.5 |
|---|---|---|
| **Worker behavior** | Log every event at Info level | Route through mode-aware pipeline |
| **New packages** | — | `pkg/discovery/` (4 files), `pkg/config/` (1 file) |
| **Config** | CLI flags only | `agent_config.yaml` loaded with hot-reload-ready design |
| **Agent modes** | None | Discovery / Shadow / Enforcement |
| **Persistence** | None | Baseline snapshots in `data/discovery/` |
| **Auto-generation** | Manual whitelist | Auto-generated `auto_whitelist.yaml` |
| **Prometheus metrics** | 3 collector metrics | +5 discovery/agent metrics |
| **CLI flags** | 4 flags | +3 flags (--config, --mode, --generate-report) |
| **Tests** | 7 tests + 1 benchmark | +18 tests + 2 benchmarks |
| **Dependencies** | — | `gopkg.in/yaml.v3` (config + whitelist serialization) |
| **Version** | v0.1.0 | v0.2.0 |
