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
