package collector

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParser_ProcessExec(t *testing.T) {
	parser := NewParser()

	now := time.Now().UTC()
	raw := &tetragon.GetEventsResponse{
		NodeName: "test-node",
		Time:     timestamppb.New(now),
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid:       wrapperspb.UInt32(1234),
					Binary:    "/bin/bash",
					Arguments: "-c whoami",
					Pod: &tetragon.Pod{
						Namespace:    "ztre-test",
						Name:         "vulnerable-nginx-xyz",
						Workload:     "vulnerable-nginx",
						WorkloadKind: "Deployment",
						Container: &tetragon.Container{
							Id: "containerd://abc12345",
						},
					},
				},
				Parent: &tetragon.Process{
					Pid:    wrapperspb.UInt32(1000),
					Binary: "/usr/sbin/nginx",
				},
			},
		},
	}

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatalf("expected non-nil event")
	}

	if event.EventType != EventTypeExecve {
		t.Errorf("expected EventType %v, got %v", EventTypeExecve, event.EventType)
	}
	if event.Binary != "/bin/bash" {
		t.Errorf("expected binary /bin/bash, got %v", event.Binary)
	}
	if event.ParentBinary != "/usr/sbin/nginx" {
		t.Errorf("expected parent binary /usr/sbin/nginx, got %v", event.ParentBinary)
	}
	if event.Namespace != "ztre-test" {
		t.Errorf("expected namespace ztre-test, got %v", event.Namespace)
	}
	if event.PodName != "vulnerable-nginx-xyz" {
		t.Errorf("expected pod vulnerable-nginx-xyz, got %v", event.PodName)
	}
	if event.PID != 1234 {
		t.Errorf("expected pid 1234, got %v", event.PID)
	}
	if event.ParentPID != 1000 {
		t.Errorf("expected parent pid 1000, got %v", event.ParentPID)
	}
}

func TestParser_IgnoreHostEvent(t *testing.T) {
	parser := NewParser()

	raw := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid:    wrapperspb.UInt32(4321),
					Binary: "/usr/bin/dockerd",
					Pod:    nil, // Host process without Pod metadata
				},
			},
		},
	}

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event != nil {
		t.Fatalf("expected nil event for host process without pod, got: %+v", event)
	}
}

func TestParser_ProcessExit(t *testing.T) {
	parser := NewParser()

	raw := &tetragon.GetEventsResponse{
		NodeName: "worker-node",
		Time:     timestamppb.New(time.Now().UTC()),
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{
				Process: &tetragon.Process{
					Pid:       wrapperspb.UInt32(5678),
					Binary:    "/bin/curl",
					Arguments: "http://attacker.com",
					Pod: &tetragon.Pod{
						Namespace: "ztre-test",
						Name:      "victim-pod",
						Container: &tetragon.Container{
							Id: "containerd://exit-container",
						},
					},
				},
				Parent: &tetragon.Process{
					Pid:    wrapperspb.UInt32(1000),
					Binary: "/bin/bash",
				},
			},
		},
	}

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected non-nil event")
	}

	if event.EventType != EventTypeExit {
		t.Errorf("expected EventTypeExit, got %v", event.EventType)
	}
	if event.Binary != "/bin/curl" {
		t.Errorf("expected binary /bin/curl, got %s", event.Binary)
	}
	if event.ParentBinary != "/bin/bash" {
		t.Errorf("expected parent binary /bin/bash, got %s", event.ParentBinary)
	}
	if event.ParentPID != 1000 {
		t.Errorf("expected parent PID 1000, got %d", event.ParentPID)
	}
	if event.ContainerID != "containerd://exit-container" {
		t.Errorf("expected container ID containerd://exit-container, got %s", event.ContainerID)
	}
}

func TestParser_ProcessKprobe(t *testing.T) {
	parser := NewParser()

	raw := &tetragon.GetEventsResponse{
		NodeName: "worker-node",
		Time:     timestamppb.New(time.Now().UTC()),
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Pid:    wrapperspb.UInt32(9999),
					Binary: "/usr/bin/python3",
					Pod: &tetragon.Pod{
						Namespace: "ztre-test",
						Name:      "python-app",
						Container: &tetragon.Container{
							Id: "containerd://kprobe-container",
						},
					},
				},
				Parent: &tetragon.Process{
					Pid:    wrapperspb.UInt32(8888),
					Binary: "/usr/sbin/sshd",
				},
			},
		},
	}

	event, err := parser.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event == nil {
		t.Fatal("expected non-nil event")
	}

	if event.EventType != EventTypeKprobe {
		t.Errorf("expected EventTypeKprobe, got %v", event.EventType)
	}
	if event.Binary != "/usr/bin/python3" {
		t.Errorf("expected binary /usr/bin/python3, got %s", event.Binary)
	}
	if event.ParentBinary != "/usr/sbin/sshd" {
		t.Errorf("expected parent binary /usr/sbin/sshd, got %s", event.ParentBinary)
	}
	if event.ContainerID != "containerd://kprobe-container" {
		t.Errorf("expected container ID containerd://kprobe-container, got %s", event.ContainerID)
	}
}

func TestParser_EdgeCases(t *testing.T) {
	parser := NewParser()

	// Nil response
	ev, err := parser.Parse(nil)
	if err != nil || ev != nil {
		t.Fatalf("expected nil event and nil error for nil response, got ev=%v, err=%v", ev, err)
	}

	// Empty event
	ev, err = parser.Parse(&tetragon.GetEventsResponse{})
	if err != nil || ev != nil {
		t.Fatalf("expected nil event for empty response, got ev=%v, err=%v", ev, err)
	}

	// Process without Pod namespace
	ev, err = parser.Parse(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pod: &tetragon.Pod{
						Namespace: "",
					},
				},
			},
		},
	})
	if err != nil || ev != nil {
		t.Fatalf("expected nil event for pod with empty namespace, got ev=%v, err=%v", ev, err)
	}
}
