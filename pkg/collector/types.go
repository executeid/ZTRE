package collector

import (
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// EventType represents the category of the security event intercepted by Tetragon.
type EventType string

const (
	EventTypeExecve     EventType = "execve"
	EventTypeExit       EventType = "exit"
	EventTypeFileAccess EventType = "file_access"
	EventTypeKprobe     EventType = "kprobe"
	EventTypeUnknown    EventType = "unknown"
)

// SecurityEvent is the normalized, structured security event data model for ZTRE.
type SecurityEvent struct {
	Timestamp      time.Time                  `json:"timestamp"`
	EventType      EventType                  `json:"event_type"`
	PID            uint32                     `json:"pid"`
	Binary         string                     `json:"binary"`
	Arguments      string                     `json:"arguments"`
	ParentPID      uint32                     `json:"parent_pid"`
	ParentBinary   string                     `json:"parent_binary"`
	Namespace      string                     `json:"namespace"`
	PodName        string                     `json:"pod_name"`
	ContainerID    string                     `json:"container_id"`
	NodeName       string                     `json:"node_name"`
	WorkloadKind   string                     `json:"workload_kind,omitempty"`
	WorkloadName   string                     `json:"workload_name,omitempty"`
	RawResponse    *tetragon.GetEventsResponse `json:"-"`
}
