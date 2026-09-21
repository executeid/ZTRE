package testutil

import (
	"time"

	"github.com/executeid/ztre/pkg/collector"
)

// EventOption allows customizing a generated SecurityEvent.
type EventOption func(*collector.SecurityEvent)

// WithTimestamp sets the timestamp on the event.
func WithTimestamp(ts time.Time) EventOption {
	return func(e *collector.SecurityEvent) {
		e.Timestamp = ts
	}
}

// WithEventType sets the EventType (default: collector.EventTypeExecve).
func WithEventType(eventType collector.EventType) EventOption {
	return func(e *collector.SecurityEvent) {
		e.EventType = eventType
	}
}

// WithPID sets the process and parent process IDs.
func WithPID(pid, parentPID uint32) EventOption {
	return func(e *collector.SecurityEvent) {
		e.PID = pid
		e.ParentPID = parentPID
	}
}

// WithArguments sets the process arguments.
func WithArguments(args string) EventOption {
	return func(e *collector.SecurityEvent) {
		e.Arguments = args
	}
}

// WithPodName sets the pod name.
func WithPodName(podName string) EventOption {
	return func(e *collector.SecurityEvent) {
		e.PodName = podName
	}
}

// WithWorkloadKind sets the workload kind (e.g. Deployment, DaemonSet).
func WithWorkloadKind(kind string) EventOption {
	return func(e *collector.SecurityEvent) {
		e.WorkloadKind = kind
	}
}

// WithContainerID sets the container ID.
func WithContainerID(cid string) EventOption {
	return func(e *collector.SecurityEvent) {
		e.ContainerID = cid
	}
}

// MakeEvent generates a synthetic collector.SecurityEvent with configurable fields:
// parent, child, namespace, workload, and node. Optional EventOption modifiers can be passed.
func MakeEvent(parent, child, namespace, workload, node string, opts ...EventOption) *collector.SecurityEvent {
	binary := ""
	if child != "" {
		binary = "/usr/bin/" + child
	}
	parentBinary := ""
	if parent != "" {
		parentBinary = "/usr/sbin/" + parent
	}

	ev := &collector.SecurityEvent{
		Timestamp:    time.Now().UTC(),
		EventType:    collector.EventTypeExecve,
		PID:          1234,
		ParentPID:    1000,
		Binary:       binary,
		Arguments:    "",
		ParentBinary: parentBinary,
		Namespace:    namespace,
		PodName:      workload + "-pod-abc",
		ContainerID:  "container-123",
		NodeName:     node,
		WorkloadKind: "Deployment",
		WorkloadName: workload,
	}

	for _, opt := range opts {
		opt(ev)
	}

	return ev
}

// MakeEventWithTime is a convenience helper for creating events with an explicit timestamp.
func MakeEventWithTime(parent, child, namespace, workload, node string, ts time.Time, opts ...EventOption) *collector.SecurityEvent {
	allOpts := append([]EventOption{WithTimestamp(ts)}, opts...)
	return MakeEvent(parent, child, namespace, workload, node, allOpts...)
}
